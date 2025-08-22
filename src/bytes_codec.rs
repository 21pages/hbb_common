use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone, Copy)]
pub struct BytesCodec {
    state: DecodeState,
    raw: bool,
    max_packet_length: usize,
}

#[derive(Debug, Clone, Copy)]
enum DecodeState {
    Head,
    Data(usize),
}

impl Default for BytesCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl BytesCodec {
    pub fn new() -> Self {
        Self {
            state: DecodeState::Head,
            raw: false,
            max_packet_length: usize::MAX,
        }
    }

    pub fn set_raw(&mut self) {
        self.raw = true;
    }

    pub fn set_max_packet_length(&mut self, n: usize) {
        self.max_packet_length = n;
    }

    fn decode_head(&mut self, src: &mut BytesMut) -> io::Result<Option<usize>> {
        if src.is_empty() {
            return Ok(None);
        }
        let head_len = ((src[0] & 0x3) + 1) as usize;
        if src.len() < head_len {
            return Ok(None);
        }
        let mut n = src[0] as usize;
        if head_len > 1 {
            n |= (src[1] as usize) << 8;
        }
        if head_len > 2 {
            n |= (src[2] as usize) << 16;
        }
        if head_len > 3 {
            n |= (src[3] as usize) << 24;
        }
        n >>= 2;
        if n > self.max_packet_length {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Too big packet"));
        }
        src.advance(head_len);
        src.reserve(n);
        Ok(Some(n))
    }

    fn decode_data(&self, n: usize, src: &mut BytesMut) -> io::Result<Option<BytesMut>> {
        if src.len() < n {
            return Ok(None);
        }
        Ok(Some(src.split_to(n)))
    }
}

impl Decoder for BytesCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        if self.raw {
            if !src.is_empty() {
                let len = src.len();
                return Ok(Some(src.split_to(len)));
            } else {
                return Ok(None);
            }
        }
        let n = match self.state {
            DecodeState::Head => match self.decode_head(src)? {
                Some(n) => {
                    self.state = DecodeState::Data(n);
                    n
                }
                None => return Ok(None),
            },
            DecodeState::Data(n) => n,
        };

        match self.decode_data(n, src)? {
            Some(data) => {
                self.state = DecodeState::Head;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decode(buf)
    }
}

impl Encoder<Bytes> for BytesCodec {
    type Error = io::Error;

    fn encode(&mut self, data: Bytes, buf: &mut BytesMut) -> Result<(), io::Error> {
        if self.raw {
            buf.reserve(data.len());
            buf.put(data);
            return Ok(());
        }
        if data.len() <= 0x3F {
            buf.put_u8((data.len() << 2) as u8);
        } else if data.len() <= 0x3FFF {
            buf.put_u16_le((data.len() << 2) as u16 | 0x1);
        } else if data.len() <= 0x3FFFFF {
            let h = (data.len() << 2) as u32 | 0x2;
            buf.put_u16_le((h & 0xFFFF) as u16);
            buf.put_u8((h >> 16) as u8);
        } else if data.len() <= 0x3FFFFFFF {
            buf.put_u32_le((data.len() << 2) as u32 | 0x3);
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Overflow"));
        }
        buf.extend(data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_codec1() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.resize(0x3F, 1);
        assert!(codec.encode(bytes.into(), &mut buf).is_ok());
        let buf_saved = buf.clone();
        assert_eq!(buf.len(), 0x3F + 1);
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0x3F);
            assert_eq!(res[0], 1);
        } else {
            panic!();
        }
        let mut codec2 = BytesCodec::new();
        let mut buf2 = BytesMut::new();
        if let Ok(None) = codec2.decode(&mut buf2) {
        } else {
            panic!();
        }
        buf2.extend(&buf_saved[0..1]);
        if let Ok(None) = codec2.decode(&mut buf2) {
        } else {
            panic!();
        }
        buf2.extend(&buf_saved[1..]);
        if let Ok(Some(res)) = codec2.decode(&mut buf2) {
            assert_eq!(res.len(), 0x3F);
            assert_eq!(res[0], 1);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_codec2() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let mut bytes: Vec<u8> = Vec::new();
        assert!(codec.encode("".into(), &mut buf).is_ok());
        assert_eq!(buf.len(), 1);
        bytes.resize(0x3F + 1, 2);
        assert!(codec.encode(bytes.into(), &mut buf).is_ok());
        assert_eq!(buf.len(), 0x3F + 2 + 2);
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0);
        } else {
            panic!();
        }
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0x3F + 1);
            assert_eq!(res[0], 2);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_codec3() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.resize(0x3F - 1, 3);
        assert!(codec.encode(bytes.into(), &mut buf).is_ok());
        assert_eq!(buf.len(), 0x3F + 1 - 1);
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0x3F - 1);
            assert_eq!(res[0], 3);
        } else {
            panic!();
        }
    }
    #[test]
    fn test_codec4() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.resize(0x3FFF, 4);
        assert!(codec.encode(bytes.into(), &mut buf).is_ok());
        assert_eq!(buf.len(), 0x3FFF + 2);
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0x3FFF);
            assert_eq!(res[0], 4);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_codec5() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.resize(0x3FFFFF, 5);
        assert!(codec.encode(bytes.into(), &mut buf).is_ok());
        assert_eq!(buf.len(), 0x3FFFFF + 3);
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0x3FFFFF);
            assert_eq!(res[0], 5);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_codec6() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.resize(0x3FFFFF + 1, 6);
        assert!(codec.encode(bytes.into(), &mut buf).is_ok());
        let buf_saved = buf.clone();
        assert_eq!(buf.len(), 0x3FFFFF + 4 + 1);
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0x3FFFFF + 1);
            assert_eq!(res[0], 6);
        } else {
            panic!();
        }
        let mut codec2 = BytesCodec::new();
        let mut buf2 = BytesMut::new();
        buf2.extend(&buf_saved[0..1]);
        if let Ok(None) = codec2.decode(&mut buf2) {
        } else {
            panic!();
        }
        buf2.extend(&buf_saved[1..6]);
        if let Ok(None) = codec2.decode(&mut buf2) {
        } else {
            panic!();
        }
        buf2.extend(&buf_saved[6..]);
        if let Ok(Some(res)) = codec2.decode(&mut buf2) {
            assert_eq!(res.len(), 0x3FFFFF + 1);
            assert_eq!(res[0], 6);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_codec7() {
        use bytes::BytesMut;
        use std::io;

        // Wrapper: forwards decode only; no decode_eof -> triggers trait default decode_eof (errors when bytes remain)
        struct DefaultEof<'a>(&'a mut BytesCodec);
        impl<'a> tokio_util::codec::Decoder for DefaultEof<'a> {
            type Item = BytesMut;
            type Error = io::Error;
            fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
                self.0.decode(src)
            }
        }

        // A) Incomplete header: default decode_eof reproduces "bytes remaining on stream"
        let len = 0x40usize; // needs 2-byte header
        let h = ((len as u16) << 2) | 0x1;
        let mut codec_def = BytesCodec::new();
        let mut wrapper = DefaultEof(&mut codec_def);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[(h & 0xFF) as u8]); // only low byte -> header incomplete
        let err = tokio_util::codec::Decoder::decode_eof(&mut wrapper, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);

        // Our decode_eof: no error, returns None (does not clear buf)
        let mut codec_ok = BytesCodec::new();
        let mut buf2 = BytesMut::new();
        buf2.extend_from_slice(&[(h & 0xFF) as u8]);
        let res = tokio_util::codec::Decoder::decode_eof(&mut codec_ok, &mut buf2).unwrap();
        assert!(res.is_none());
        assert!(!buf2.is_empty());

        // B) Incomplete body: default decode_eof still errors
        let len2 = 2usize;
        let h2 = ((len2 as u16) << 2) | 0x1;
        let mut codec_def2 = BytesCodec::new();
        let mut wrapper2 = DefaultEof(&mut codec_def2);
        let mut buf3 = BytesMut::new();
        buf3.extend_from_slice(&[(h2 & 0xFF) as u8, (h2 >> 8) as u8]); // header complete
        buf3.extend_from_slice(&[0xAA]); // only 1 data byte, missing 1
        let err2 = tokio_util::codec::Decoder::decode_eof(&mut wrapper2, &mut buf3).unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::Other);

        // New decode_eof: no error, returns None (does not clear buf)
        let mut codec_ok2 = BytesCodec::new();
        let mut buf4 = BytesMut::new();
        buf4.extend_from_slice(&[(h2 & 0xFF) as u8, (h2 >> 8) as u8]);
        buf4.extend_from_slice(&[0xAA]);
        let res2 = tokio_util::codec::Decoder::decode_eof(&mut codec_ok2, &mut buf4).unwrap();
        assert!(res2.is_none());
        assert!(!buf4.is_empty());

        // C) At EOF with a complete frame, still decodes correctly
        let mut encoded = BytesMut::new();
        encoded.extend_from_slice(&[((3usize << 2) as u8)]);
        encoded.extend_from_slice(b"abc");
        let mut codec_ok3 = BytesCodec::new();
        let mut buf5 = encoded.clone();
        if let Some(frame) =
            tokio_util::codec::Decoder::decode_eof(&mut codec_ok3, &mut buf5).unwrap()
        {
            assert_eq!(frame, BytesMut::from(&b"abc"[..]));
        } else {
            panic!();
        }
    }

    #[test]
    fn test_codec8() {
        use bytes::BytesMut;

        // Prepare two encoded frames: "hello" and "world!"
        let mut encoder = BytesCodec::new();
        let mut f1 = BytesMut::new();
        let mut f2 = BytesMut::new();
        assert!(encoder.encode("hello".into(), &mut f1).is_ok());
        assert!(encoder.encode("world!".into(), &mut f2).is_ok());

        // Case 1: append half of frame1, then append the remaining half -> decode frame1
        {
            let mut codec = BytesCodec::new();
            let mut buf = BytesMut::new();
            let mid = f1.len() / 2;
            buf.extend_from_slice(&f1[..mid]);
            // Not enough for a frame yet
            assert!(matches!(codec.decode(&mut buf).unwrap(), None));
            // Append the rest of frame1
            buf.extend_from_slice(&f1[mid..]);
            // Now we should get frame1
            if let Some(frame) = codec.decode(&mut buf).unwrap() {
                assert_eq!(frame, BytesMut::from(&b"hello"[..]));
            } else {
                panic!();
            }
            // No more frames
            assert!(codec.decode(&mut buf).unwrap().is_none());
        }

        // Case 2: append half of frame1, then append remaining of frame1 plus entire frame2
        // Expect to decode frame1 first, then frame2 on next decode call
        {
            let mut codec = BytesCodec::new();
            let mut buf = BytesMut::new();
            let mid = f1.len() / 2;
            buf.extend_from_slice(&f1[..mid]);
            assert!(codec.decode(&mut buf).unwrap().is_none());
            // Append rest of frame1 and all of frame2
            buf.extend_from_slice(&f1[mid..]);
            buf.extend_from_slice(&f2);
            // First decode returns frame1
            if let Some(frame1) = codec.decode(&mut buf).unwrap() {
                assert_eq!(frame1, BytesMut::from(&b"hello"[..]));
            } else {
                panic!();
            }
            // Second decode returns frame2
            if let Some(frame2) = codec.decode(&mut buf).unwrap() {
                assert_eq!(frame2, BytesMut::from(&b"world!"[..]));
            } else {
                panic!();
            }
            // No more frames
            assert!(codec.decode(&mut buf).unwrap().is_none());
        }

        // Case 3: append frame1 completely and half of frame2, then append the remaining of frame2
        // Expect to decode frame1 immediately, then frame2 after remaining bytes arrive
        {
            let mut codec = BytesCodec::new();
            let mut buf = BytesMut::new();
            let mid2 = f2.len() / 2;
            buf.extend_from_slice(&f1);
            buf.extend_from_slice(&f2[..mid2]);
            // First decode returns frame1
            if let Some(frame1) = codec.decode(&mut buf).unwrap() {
                assert_eq!(frame1, BytesMut::from(&b"hello"[..]));
            } else {
                panic!();
            }
            // Not enough for frame2 yet
            assert!(codec.decode(&mut buf).unwrap().is_none());
            // Append the rest of frame2
            buf.extend_from_slice(&f2[mid2..]);
            // Now we should get frame2
            if let Some(frame2) = codec.decode(&mut buf).unwrap() {
                assert_eq!(frame2, BytesMut::from(&b"world!"[..]));
            } else {
                panic!();
            }
            assert!(codec.decode(&mut buf).unwrap().is_none());
        }
    }
}
