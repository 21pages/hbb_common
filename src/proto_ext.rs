use crate::rendezvous_proto;

/// Helper functions for ControllingStrategy bitwise mask operations
impl rendezvous_proto::ControllingStrategy {
    /// Set a feature bit in the disabled_features (disable the feature)
    pub fn disable_feature(&mut self, feature: rendezvous_proto::controlling_strategy::Feature) {
        use protobuf::Enum;
        let bit = feature.value() as usize;
        let byte_index = bit / 8;
        let bit_offset = bit % 8;

        let mut mask_vec = self.disabled_features.to_vec();
        while mask_vec.len() <= byte_index {
            mask_vec.push(0);
        }
        mask_vec[byte_index] |= 1 << bit_offset;
        self.disabled_features = mask_vec.into();
    }

    /// Clear a feature bit in the disabled_features (enable the feature)
    pub fn enable_feature(&mut self, feature: rendezvous_proto::controlling_strategy::Feature) {
        use protobuf::Enum;
        let bit = feature.value() as usize;
        let byte_index = bit / 8;
        let bit_offset = bit % 8;

        let mut mask_vec = self.disabled_features.to_vec();
        if byte_index < mask_vec.len() {
            mask_vec[byte_index] &= !(1 << bit_offset);
            self.disabled_features = mask_vec.into();
        }
    }

    /// Check if a feature is disabled
    pub fn is_feature_disabled(
        &self,
        feature: rendezvous_proto::controlling_strategy::Feature,
    ) -> bool {
        use protobuf::Enum;
        let bit = feature.value() as usize;
        let byte_index = bit / 8;
        let bit_offset = bit % 8;

        if byte_index >= self.disabled_features.len() {
            return false;
        }
        (self.disabled_features[byte_index] & (1 << bit_offset)) != 0
    }

    /// Get all disabled features
    pub fn get_disabled_features(&self) -> Vec<rendezvous_proto::controlling_strategy::Feature> {
        use protobuf::Enum;
        let mut result = Vec::new();
        for (byte_index, &byte) in self.disabled_features.iter().enumerate() {
            for bit_offset in 0..8 {
                if (byte & (1 << bit_offset)) != 0 {
                    let bit_value = (byte_index * 8 + bit_offset) as i32;
                    if let Some(feature) =
                        rendezvous_proto::controlling_strategy::Feature::from_i32(bit_value)
                    {
                        result.push(feature);
                    }
                }
            }
        }
        result
    }
}
