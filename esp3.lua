-- 
-- Wireshark Plugin for EnOcean sensor data packet
-- 
-- EnOcean Serial Protocol 3 (ESP3)
-- Packet Type 1: RADIO_ERP1
-- Packet Type 10: RADIO_ERP2
-- 

-- declare some Fields to be read
ip_src_f = Field.new("ip.src")
ip_dst_f = Field.new("ip.dst")
tcp_src_f = Field.new("tcp.srcport")
tcp_dst_f = Field.new("tcp.dstport")
udp_src_f = Field.new("udp.srcport")
udp_dst_f = Field.new("udp.dstport")

-- declare our (pseudo) protocol
esp3_proto = Proto("esp3","EnOcean Serial Protocol 3 (ESP3)")

-- create the fields for our "protocol"
decoded_F = ProtoField.string("en.decoded", "EnOcean sensor packet") 

-- for bit field
    F_flag_size1_bit_0123 = ProtoField.uint8("esp3.flag_bit","b0123", base.HEX, None, 0x0F)
    F_flag_size1_bit_4567 = ProtoField.uint8("og.flag_bit","b4567", base.HEX, None, 0xF0)
    F_flag_size1_bit0 = ProtoField.uint8("esp3.flag_bit","b0", base.HEX, None, 0x01)
    F_flag_size1_bit1 = ProtoField.uint8("esp3.flag_bit","b1", base.HEX, None, 0x02)
    F_flag_size1_bit2 = ProtoField.uint8("esp3.flag_bit","b2", base.HEX, None, 0x04)
    F_flag_size1_bit3 = ProtoField.uint8("esp3.flag_bit","b3", base.HEX, None, 0x08)
    F_flag_size1_bit4 = ProtoField.uint8("esp3.flag_bit","b4", base.HEX, None, 0x10)
    F_flag_size1_bit5 = ProtoField.uint8("esp3.flag_bit","b5", base.HEX, None, 0x20)
    F_flag_size1_bit6 = ProtoField.uint8("esp3.flag_bit","b6", base.HEX, None, 0x40)
    F_flag_size1_bit7 = ProtoField.uint8("esp3.flag_bit","b7", base.HEX, None, 0x80)

    F_flag_size1_bit_567 = ProtoField.uint8("esp3.flag_bit","b567", base.HEX, None, 0xE0)

-- add the field to the protocol
esp3_proto.fields = {
    decoded_F, 
    F_flag_size1_bit_0123, F_flag_size1_bit_4567, 
    F_flag_size1_bit0, F_flag_size1_bit1, F_flag_size1_bit2, F_flag_size1_bit3, F_flag_size1_bit4, F_flag_size1_bit5, F_flag_size1_bit6, F_flag_size1_bit7, 
    F_flag_size1_bit_567
}

ESP3_NOT_FOUND = 0
ESP3_TYPE1 = 1
ESP3_TYPE10 = 10

YOUR_EXTRA_HEADER_SIZE = 0

-- create a function to "postdissect" each frame
function esp3_proto.dissector(buf, pinfo, tree)
    -- obtain the current values the protocol fields
    local tcp_src = tcp_src_f()
    local tcp_dst = tcp_dst_f()
    local udp_src = udp_src_f()
    local udp_dst = udp_dst_f()
    
    -- start position of analysis (ignore Ethernet frame, IP frame and TCP/UDP header)
    -- If ESP3 data starts at the beginning of UDP / TCP data, 
    -- parsing is started after the UDP / TCP header.
    -- Or, if there are some extra header data in addition to the original ESP3 data, 
    -- the parsing needs to skip the extra header size.
    local ip_header_length = (buf(14,1):uint() - 0x40) * 4
    local skip_len
    if tcp_src then
       skip_len = 14 + ip_header_length + 20 -- eth, ip, tcp(header)
    end
    if udp_src then
       skip_len = 14 + ip_header_length + 8 -- eth, ip, udp(header)
    end
    skip_len = skip_len + YOUR_EXTRA_HEADER_SIZE
    
    -- check if the packet is a target
    local subtree
    local esp3_proto_type = ESP3_NOT_FOUND
    if tcp_src or udp_src then
        local sync_byte = buf(skip_len+0, 1):uint()
        local data_length = buf(skip_len+1, 2):uint()
        local optional_length = buf(skip_len+3, 1):uint()
        local packet_type = buf(skip_len+4, 1):uint()
        
        if sync_byte == 0x55 and packet_type == 0x01 then
            esp3_proto_type = ESP3_TYPE1
            subtree = tree:add(esp3_proto, "EnOcean Serial Protocol 3 (ESP3)")
                :add_expert_info(PI_DEBUG, PI_NOTE, "EnOcean Serial Protocol 3 (ESP3) - Packet Type 1: RADIO_ERP1, ver.0.1")
        end
        if sync_byte == 0x55 and packet_type == 0x0A then
            esp3_proto_type = ESP3_TYPE10
            subtree = tree:add(esp3_proto, "EnOcean Serial Protocol 3 (ESP3)")
                :add_expert_info(PI_DEBUG, PI_NOTE, "EnOcean Serial Protocol 3 (ESP3) - Packet Type 10: RADIO_ERP2, ver.0.1")
        end

        -- ESP3 Type1 ?
        if esp3_proto_type == ESP3_TYPE1 then
            local subtree_add
            local pos = 0
            subtree_add, pos = wrap_tree_add_str(subtree, buf(skip_len, data_length+7+optional_length), "EnOcean Serial Protocol 3 (ESP3) - Packet Type 1", 0, data_length+7+optional_length)
            decode_esp3_type1(subtree_add, buf(skip_len, buf:len()-skip_len), pinfo, tree)
        end
        -- ESP3 Type10 ?
        if esp3_proto_type == ESP3_TYPE10 then
            local subtree_add
            local pos = 0
            subtree_add, pos = wrap_tree_add_str(subtree, buf(skip_len, data_length+7+optional_length), "EnOcean Serial Protocol 3 (ESP3) - Packet Type 10", 0, data_length+7+optional_length)
            decode_esp3_type10(subtree_add, buf(skip_len, buf:len()-skip_len), pinfo, tree)
        end
    end

    ------------------------------------
    -- build trees
    ------------------------------------

    -- ESP3 Type1
    function decode_esp3_type1(subtree, buf, pinfo, tree)
        local sync_byte = buf(0, 1):uint()
        local data_length = buf(1, 2):uint()
        local optional_length = buf(3, 1):uint()
        local packet_type = buf(4, 1):uint()
        if sync_byte == 0x55 and packet_type == 0x01 then
            
            local subtree_add
            local pos = 0
            local tmp
            
            -- header
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Sync. Byte", pos, 1);
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Data Length", pos, 2);
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Optional Length", pos, 1);
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Packet Type", pos, 1);
            
            -- CRC
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "CRC8H", pos, 1);
            
            -- data
            if data_length > 0 then
                subtree_add, tmp = wrap_tree_add_str(subtree, buf, "ERP1 radio telegram (Raw data)", pos, data_length);
                decode_erp1_radio(subtree_add, buf(pos, data_length), pinfo, tree)
                pos = tmp
            else
                wrap_tree_add_empty(subtree, "(no ERP1 radio telegram)");
            end
            
            -- Optional Data
            if optional_length > 0 then
                subtree_add, pos = wrap_tree_add_uint(subtree, buf, "SubTelNum", pos, 1);
                subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Destination ID", pos, 4);
                subtree_add, pos = wrap_tree_add_uint(subtree, buf, "dBm", pos, 1);
                subtree_add, pos = wrap_tree_add_uint(subtree, buf, "SecurityLevel", pos, 1);
            else
                wrap_tree_add_empty(subtree, "(no Optional Data)");
            end
            
            -- CRC
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "CRC8D", pos, 1);

        end
    end

    -- ERP2 radio protocol (Data contents for Length > 6 Bytes)
    function decode_erp1_radio(subtree, buf, pinfo, tree)
        local subtree_add
        local pos = 0
        local tmp
        
        -- RORG
        subtree_add, pos = wrap_tree_add_uint(subtree, buf, "RORG", pos, 1);
        
        -- DATA
        subtree_add, pos = wrap_tree_add_uint(subtree, buf, "DATA", pos, buf:len()-pos-5);
        
        -- TXID
        subtree_add, pos = wrap_tree_add_uint(subtree, buf, "TXID", pos, 4);
        
        -- STATUS
        subtree_add, pos = wrap_tree_add_uint(subtree, buf, "STATUS", pos, 1);
        
    end

    -- ESP3 Type10
    function decode_esp3_type10(subtree, buf, pinfo, tree)
        local sync_byte = buf(0, 1):uint()
        local data_length = buf(1, 2):uint()
        local packet_type = buf(4, 1):uint()
        if sync_byte == 0x55 and packet_type == 0x0A then
            
            local subtree_add
            local pos = 0
            local tmp
            
            -- header
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Sync. Byte", pos, 1);
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Data Length", pos, 2);
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Optional Length", pos, 1);
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Packet Type", pos, 1);
            
            -- CRC
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "CRC8H", pos, 1);
            
            -- data
            subtree_add, tmp = wrap_tree_add_str(subtree, buf, "ERP2 radio protocol telegram (Raw data)", pos, data_length);
            decode_erp2_radio_6(subtree_add, buf(pos, data_length), pinfo, tree)
            pos = tmp
            
            -- Optional Data
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "SubTelNum", pos, 1);
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "dBm", pos, 1);
            
            -- CRC
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "CRC8D", pos, 1);

        end
    end

    -- ERP2 radio protocol (Data contents for Length > 6 Bytes)
    function decode_erp2_radio_6(subtree, buf, pinfo, tree)
        local header = buf(0, 1):uint()
        local opt_data_len = 0
        local subtree_add
        local subtree_bit
        local pos = 0
        local tmp
        
        -- header
        subtree_add, tmp = wrap_tree_add_uint(subtree, buf, "Header", pos, 1);
        subtree_bit = wrap_tree_add_bit(F_flag_size1_bit_567, subtree_add, buf, ": Address Control", pos, 1)
        subtree_bit = wrap_tree_add_bit(F_flag_size1_bit4, subtree_add, buf, ": Extended header availablel", pos, 1)
        subtree_bit = wrap_tree_add_bit(F_flag_size1_bit_0123, subtree_add, buf, ": Telegram type (R-ORG)", pos, 1)
        pos = tmp
        
        -- Extended Header
        if bit32.band(header, 0x10) == 0x10 then
            subtree_add, tmp = wrap_tree_add_uint(subtree, buf, "Extended Header", pos, 1);
            subtree_bit, tmp = wrap_tree_add_bit(F_flag_size1_bit_4567, subtree_add, buf, ": Repeater count", pos, 1)
            subtree_bit, tmp = wrap_tree_add_bit(F_flag_size1_bit_0123, subtree_add, buf, ": Length of Optional data", pos, 1)
            opt_data_len = bit32.band(buf(pos, 1):uint(), 0x0F)
            pos = tmp
        else
            wrap_tree_add_empty(subtree, "(no Extended Header)");
        end
        
        -- Extended Telegram type
        if bit32.band(header, 0x0F) == 0x0F then
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Extended Telegram type", pos, 1);
        else
            wrap_tree_add_empty(subtree, "(no Extended Telegram type)");
        end
        
        -- Originator-ID
        -- Destination-ID
        if bit32.band(header, 0xE0) == 0x00 then
            -- 000: Originator-ID 24 bit; no Destination-ID
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Originator-ID 24 bit", pos, 3);
            wrap_tree_add_empty(subtree, "(no Destination-ID)");
        elseif bit32.band(header, 0xE0) == 0x20 then
            -- 001: Originator-ID 32 bit; no Destination-ID
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Originator-ID 32 bit", pos, 4);
            wrap_tree_add_empty(subtree, "(no Destination-ID)");
        elseif bit32.band(header, 0xE0) == 0x40 then
            -- 010: Originator-ID 32 bit, Destination-ID 32 bit
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Originator-ID 32 bit", pos, 4);
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Destination-ID 32 bit", pos, 4);
        elseif bit32.band(header, 0xE0) == 0x60 then
            -- 011: Originator-ID 48 bit, no Destination-ID
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "Originator-ID 48 bit", pos, 6);
            wrap_tree_add_empty(subtree, "(no Destination-ID)");
        end

        -- Data_DL
        if bit32.band(header, 0x0F) == 0x00 then
            -- 0000: RPS telegram (0xF6)
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "RPS telegram (0xF6)", pos, 1);
        elseif bit32.band(header, 0x0F) == 0x01 then
            -- 0001: 1BS telegram (0xD5)
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "1BS telegram (0xD5)", pos, 1);
        elseif bit32.band(header, 0x0F) == 0x02 then
            -- 0010: 4BS telegram (0xA5)
            subtree_add, pos = wrap_tree_add_uint(subtree, buf, "4BS telegram (0xA5)", pos, 4);
        elseif bit32.band(header, 0x0F) == 0x04 then
            -- 0100: Variable length data telegram (0xD2)
            subtree_add, pos = wrap_tree_add_str(subtree, buf, "0100: Variable length data telegram (0xD2)", pos, buf:len()-pos-1);
        else
            wrap_tree_add_empty(subtree, "TBD");
        end

        -- Optional Data
        if opt_data_len > 0 then
        else
            wrap_tree_add_empty(subtree, "(no Optional Data)");
        end

        -- CRC
        subtree_add, pos = wrap_tree_add_uint(subtree, buf, "CRC", pos, 1);

    end

    ------------------------------------
    -- Helper
    ------------------------------------
    
    function wrap_tree_add_bit(field, tree, buf, title, pos, len)
        local subtree_add = tree:add(field, buf(pos,len), buf(pos,len):uint()):append_text(title)
        return subtree_add, (pos + len)
    end

    function wrap_tree_add_empty(tree, title)
        tree:add(decoded_F):set_text(title)
    end
    
    function wrap_tree_add_uint(tree, buf, title, pos, len)
        local val = buf(pos,len):uint()
        return wrap_tree_add_com(tree, buf(pos,len), title, pos, len, tostring(val))
    end

    function wrap_tree_add_str(tree, buf, title, pos, len)
        return wrap_tree_add_com(tree, buf(pos,len), title, pos, len, buf(pos,len):string())
    end

    function wrap_tree_add_com(tree, buf, title, pos, len, decoded)
        local text = string.format("%s: 0x%s (%s)", title, tostring(buf), decoded)
        local subtree_add = tree:add(decoded_F, buf):set_text(text)
        return subtree_add, (pos + len)
    end

end

-- register our protocol as a postdissector
register_postdissector(esp3_proto)
