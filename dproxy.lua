-- dproxy.lua - Wireshark dissector for DProxy (basic header + payload parsing)
local dproxy = Proto("dproxy", "DProxy Protocol")

local pkt_types = {
    [0] = "HANDSHAKE_INIT",
    [1] = "HANDSHAKE_RESPONSE",
    [2] = "HANDSHAKE_FINAL",
    [3] = "HANDSHAKE_FINALIZED",
    [4] = "CONNECT",
    [5] = "CONNECTED",
    [6] = "DISCONNECT",
    [7] = "DISCONNECTED",
    [8] = "DATA",
    [9] = "ENCRYPTED_DATA",
    [10] = "HEARTBEAT",
    [11] = "HEARTBEAT_RESPONSE",
    [12] = "ERROR"
}

local err_codes = {
    [0] = "NO_ERROR",
    [1] = "INVALID_VERSION",
    [2] = "INVALID_PACKET_TYPE",
    [3] = "INVALID_PACKET_LENGTH",
    [4] = "INVALID_HANDSHAKE_INFO",
    [5] = "HANDSHAKE_FAILED",
    [6] = "ALREADY_AUTHENTICATED",
    [7] = "INVALID_DESTINATION",
    [8] = "CONNECTION_FAILED",
    [9] = "CONNECTION_CLOSED",
    [10] = "CONNECTION_TIMEOUT",
    [11] = "INVALID_CONNECTION",
    [12] = "DECRYPT_FAILED"
}

local conn_types = {
    [0] = "TCP",
    [1] = "UDP"
}

-- header fields (Version uint8, Type uint8, Length uint16, ErrorCode uint8)
local f_version = ProtoField.uint8("dproxy.version", "Version", base.DEC)
local f_type = ProtoField.uint8("dproxy.type", "Type", base.DEC, pkt_types)
local f_length = ProtoField.uint16("dproxy.length", "Length", base.DEC)
local f_error = ProtoField.uint8("dproxy.error", "Error", base.DEC, err_codes)

-- payload fields
local f_conn_id = ProtoField.uint32("dproxy.connection_id", "ConnectionId", base.DEC)
local f_conn_type = ProtoField.uint8("dproxy.connection_type", "ConnectionType", base.DEC, conn_types)
local f_port = ProtoField.uint16("dproxy.port", "Port", base.DEC)
local f_timestamp = ProtoField.uint64("dproxy.timestamp", "Timestamp", base.DEC)
local f_payload = ProtoField.bytes("dproxy.payload", "Payload")
local f_message = ProtoField.string("dproxy.message", "Message")
local f_der = ProtoField.bytes("dproxy.der", "DERPublicKey")
local f_iv = ProtoField.bytes("dproxy.iv", "IV")
local f_ciphertext = ProtoField.bytes("dproxy.ciphertext", "Ciphertext")
local f_tag = ProtoField.bytes("dproxy.tag", "AuthenticationTag")
local f_plaintext = ProtoField.bytes("dproxy.plaintext", "Plaintext")
local f_id = ProtoField.string("dproxy.id", "Id")
local f_hello = ProtoField.string("dproxy.hello", "Hello")
local f_destination = ProtoField.string("dproxy.destination", "Destination")
local f_address = ProtoField.string("dproxy.address", "Address")
local f_data = ProtoField.bytes("dproxy.data", "Data")
local f_timestamp_sender = ProtoField.uint64("dproxy.timestamp_sender", "TimestampSender", base.DEC)
local f_timestamp_receiver = ProtoField.uint64("dproxy.timestamp_receiver", "TimestampReceiver", base.DEC)

dproxy.fields = {
    f_version,
    f_type,
    f_length,
    f_error,
    f_conn_id,
    f_conn_type,
    f_port,
    f_timestamp,
    f_payload,
    f_message,
    f_der,
    f_iv,
    f_ciphertext,
    f_tag,
    f_plaintext,
    f_id,
    f_hello,
    f_destination,
    f_address,
    f_data,
    f_timestamp_sender,
    f_timestamp_receiver
}

local function safe_read(tvb, offset, len)
    if offset + len <= tvb:len() then
        return tvb(offset, len)
    end
    return nil
end

function dissect_packet(tvb, pinfo, tree)
    local tvb_len = tvb:len()
    if tvb_len < 5 then
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    local version = tvb(0, 1):uint()
    local ptype = tvb(1, 1):uint()
    local length = tvb(2, 2):uint()
    local errc = tvb(4, 1):uint()
    local payload_offset = 5

    if version ~= 1 then
        return 0
    end

    if tvb_len < payload_offset + length then
        return -((payload_offset + length) - tvb_len)
    end

    pinfo.cols.protocol = "DPROXY"

    local subtree = tree:add(dproxy, tvb(), "DProxy Protocol")
    subtree:add(f_version, tvb(0, 1))
    subtree:add(f_type, tvb(1, 1))
    subtree:add(f_length, tvb(2, 2))
    subtree:add(f_error, tvb(4, 1))

    local payload_tvb = safe_read(tvb, payload_offset, length)

    if not payload_tvb or length == 0 then
        return 0
    end

    local ptree = subtree:add(f_payload, payload_tvb:range())

    -- helper to read length-prefixed (uint16) chunk
    local function read_len_prefixed(tvbobj, off)
        if off + 2 > tvbobj:len() then
            return nil, off
        end

        local l = tvbobj(off, 2):uint()
        off = off + 2
        if off + l > tvbobj:len() then
            return nil, off
        end

        local chunk = tvbobj(off, l)
        off = off + l
        return chunk, off
    end

    local conversation = pinfo.conversation

    -- parse by packet type
    if ptype == 0 then -- HANDSHAKE_INIT
        -- layout: [DERLen:uint16][DER bytes][HelloLen:uint16][Hello]
        local off = 0
        if length < 2+0+2+0 then
            ptree:add_expert_info(PI_MALFORMED, PI_ERROR, "HANDSHAKE_INIT too short")
            return 0
        end

        local der, off = read_len_prefixed(payload_tvb, off)
        local hello, off = read_len_prefixed(payload_tvb, off)
        ptree:add(f_der, der)
        ptree:add(f_hello, hello)
    elseif ptype == 1 then -- HANDSHAKE_RESPONSE
        -- layout: [IV][CipherLen:uint16][Ciphertext][AuthTag]
        local off = 0
        if length < 12+2+0+16 then
            ptree:add_expert_info(PI_MALFORMED, PI_ERROR, "HANDSHAKE_RESPONSE too short")
            return 0
        end

        local iv, off = payload_tvb(off, 16), off + 12
        local cipher, off = read_len_prefixed(payload_tvb, off)
        local tag, off = payload_tvb(off, 16), off + 16
        ptree:add(f_iv, iv)
        ptree:add(f_ciphertext, cipher)
        ptree:add(f_tag, tag)
    elseif ptype == 2 then -- HANDSHAKE_FINAL
        -- layout: [Plaintext]
        local off = 0
        if length <= 0 then
            ptree:add_expert_info(PI_MALFORMED, PI_ERROR, "HANDSHAKE_FINAL has no payload")
            return 0
        end

        local plaintext, off = payload_tvb, off + payload_tvb:len()
        ptree:add(f_plaintext, plaintext)
    elseif ptype == 3 then -- HANDSHAKE_FINALIZED
        -- laylout: [IdLen:uint16][Id]
        local off = 0
        if length < 2+0 then
            ptree:add_expert_info(PI_MALFORMED, PI_ERROR, "HANDSHAKE_FINALIZED too short")
            return 0
        end

        local id, off = read_len_prefixed(payload_tvb, off)
        ptree:add(f_id, id)
    elseif ptype == 4 then -- CONNECT
        -- layout: [ConnectionId:uint32][ConnectionType:uint8][DestLen:uint16][Destination][Port:uint16]
        local off = 0
        if length < 4+1+2+0+2 then
            ptree:add_expert_info(PI_MALFORMED, PI_ERROR, "CONNECT too short")
            return 0
        end

        local conn_id, off = payload_tvb(off, 4), off + 4
        local conn_type, off = payload_tvb(off, 1), off + 1
        local dest, off = read_len_prefixed(payload_tvb, off)
        local port, off = payload_tvb(off, 2), off + 2
        ptree:add(f_conn_id, conn_id)
        ptree:add(f_conn_type, conn_type)
        ptree:add(f_destination, dest)
        ptree:add(f_port, port)
    elseif ptype == 5 then -- CONNECTED
        -- layout: [ConnectionId:uint32][AddrLen:uint16][Address][Port:uint16]
        local off = 0
        if length < 4+2+0+2 then
            ptree:add_expert_info(PI_MALFORMED, PI_ERROR, "CONNECTED too short")
            return 0
        end

        local conn_id, off = payload_tvb(off, 4), off + 4
        local addr, off = read_len_prefixed(payload_tvb, off)
        local port, off = payload_tvb(off, 2), off + 2
        ptree:add(f_conn_id, conn_id)
        ptree:add(f_address, addr)
        ptree:add(f_port, port)
    elseif ptype == 6 then -- DISCONNECT
        -- layout: [ConnectionId:uint32]
        local off = 0
        if length < 4 then
            ptree:add_expert_info(PI_MALFORMED, PI_ERROR, "DISCONNECT too short")
            return 0
        end

        local conn_id, off = payload_tvb(off, 4), off + 4
        ptree:add(f_conn_id, conn_id)
    elseif ptype == 7 then -- DISCONNECTED
        -- layout: [ConnectionId:uint32]
        local off = 0
        if length < 4 then
            ptree:add_expert_info(PI_MALFORMED, PI_ERROR, "DISCONNECTED too short")
            return 0
        end

        local conn_id, off = payload_tvb(off, 4), off + 4
        ptree:add(f_conn_id, conn_id)
    elseif ptype == 8 then -- DATA
        -- layout: [ConnectionId:uint32][DataLen:uint16][Data]
        local off = 0
        if length < 4+2+0 then
            ptree:add_expert_info(PI_MALFORMED, PI_ERROR, "DATA packet too short")
            return 0
        end

        local conn_id, off = payload_tvb(off, 4), off + 4
        local data, off = read_len_prefixed(payload_tvb, off)
        ptree:add(f_conn_id, conn_id)
        ptree:add(f_data, data)
    elseif ptype == 9 then -- ENCRYPTED_DATA
        -- layout: [ConnectionId:uint32][IV][CipherLen:uint16][Ciphertext][Tag]
        local off = 0
        if length < 4 then
            ptree:add_expert_info(PI_MALFORMED, PI_ERROR, "ENCRYPTED_DATA too short")
            return 0
        end

        local conn_id, off = payload_tvb(off, 4), off + 4
        local iv, off = payload_tvb(off, 12), off + 12
        local cipher, off = read_len_prefixed(payload_tvb, off)
        local tag, off = payload_tvb(off, 16), off + 16
        ptree:add(f_conn_id, conn_id)
        ptree:add(f_iv, iv)
        ptree:add(f_ciphertext, cipher)
        ptree:add(f_tag, tag)
    elseif ptype == 10 then -- HEARTBEAT
        -- layout: [Timestamp:uint64]
        local off = 0
        if length < 8 then
            ptree:add_expert_info(PI_MALFORMED, PI_ERROR, "HEARTBEAT too short")
            return 0
        end

        local timestamp, off = payload_tvb(off, 8), off + 8
        ptree:add(f_timestamp, timestamp)
    elseif ptype == 11 then -- HEARTBEAT_RESPONSE
        -- laylout: [TimestampSender:uint64][TimestampReceiver:uint64]
        local off = 0
        if length < 8+8 then
            ptree:add_expert_info(PI_MALFORMED, PI_ERROR, "HEARTBEAT_RESPONSE too short")
            return 0
        end

        local ts_sender, off = payload_tvb(off, 8), off + 8
        local ts_receiver, off = payload_tvb(off, 8), off + 8
        ptree:add(f_timestamp_sender, ts_sender)
        ptree:add(f_timestamp_receiver, ts_receiver)
    elseif ptype == 12 then -- ERROR
        -- layout: [MsgLen:uint16][Message]
        local off = 0
        if length < 2+0 then
            ptree:add_expert_info(PI_MALFORMED, PI_ERROR, "ERROR packet too short")
            return 0
        end

        local msg, off = read_len_prefixed(payload_tvb, off)
        ptree:add(f_message, msg)
    else
        -- unknown type: leave raw payload
        return 0
    end

    pinfo.cols['info'] = (pkt_types[ptype] or "UNKNOWN") .. " [" .. (err_codes[errc] or "UNKNOWN") .. "]" .. " (" .. tostring(length) .. " bytes)"
    return payload_offset + length
end

function dproxy.dissector(tvb, pinfo, tree)
    local tvb_len = tvb:len()

    local offset = 0
    while offset < tvb_len do
        local consumed = dissect_packet(tvb:range(offset), pinfo, tree)
        if consumed > 0 then
            offset = offset + consumed
        elseif consumed == 0 then
            return 0
        else
            pinfo.desegment_offset = offset
            pinfo.desegment_len = -consumed
            return tvb_len
        end
    end

    return offset
end

-- Register on default port
local PORT = 8081
DissectorTable.get("tcp.port"):add(PORT, dproxy)
