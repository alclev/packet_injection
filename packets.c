#include "packets.h"


/* IP Segment */

/**
 * Sets the IP version for a network connection.
 *
 * @param version The IP version to set (IPv4 or IPv6).
 *
 * @returns None
 */
void IP_set_version(IP_Header_t* this, uint8_t version) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    uint8_t mask = 0x0F;
    uint8_t masked_version_n_IHL = this->version_n_IHL & mask;
    uint8_t shifted_version = version << 4;
    this->version_n_IHL = masked_version_n_IHL | shifted_version;
}

/**
 * Sets the Internet Protocol (IP) header length field (IHL).
 *
 * @param ip_header The IP header structure.
 * @param ihl The value to set for the IHL field.
 *
 * @returns None
 */
void IP_set_IHL(IP_Header_t* this, uint8_t IHL) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    uint8_t mask = 0xF0;
    uint8_t masked_version_n_IHL = this->version_n_IHL & mask;
    mask = 0x0F;
    uint8_t formatted_IHL = IHL & mask;
    this->version_n_IHL = masked_version_n_IHL | formatted_IHL;
}

/**
 * Sets the Type of Service (ToS) field in the IP header.
 *
 * @param tos The value to set for the Type of Service field.
 *
 * @returns None
 */
void IP_set_type_of_service(IP_Header_t* this, uint8_t type_of_service) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->type_of_service = type_of_service;
}

/**
 * Sets the total length field of an IP packet.
 *
 * @param packet The IP packet to modify.
 * @param length The total length value to set.
 *
 * @returns None
 */
void IP_set_total_length(IP_Header_t* this, uint16_t total_length) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->total_length = total_length;
}

/**
 * Sets the ID of the IP address.
 *
 * @param id The ID to set for the IP address.
 *
 * @returns None
 */
void IP_set_id(IP_Header_t* this, uint16_t id) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->id = id;
}

/**
 * Sets the flags for an IP address.
 *
 * This function is used to set the flags associated with an IP address.
 *
 * @param address The IP address for which the flags are to be set.
 *
 * @returns None
 */
void IP_set_flags(IP_Header_t* this, uint8_t flags) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    uint16_t mask = 0x1FFF;
    uint16_t masked_flags_n_offset = this->flags_n_offset & mask;
    uint16_t shifted_flags = flags << 13;
    this->flags_n_offset = masked_flags_n_offset | shifted_flags;
}

/**
 * Sets the offset value for an IP (Internet Protocol) address.
 *
 * @param offset The offset value to set.
 *
 * @returns None
 */
void IP_set_offset(IP_Header_t* this, uint16_t offset) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    uint16_t mask = 0xE0FF;
    uint16_t masked_flags_n_offset = this->flags_n_offset & mask;
    mask = 0x1FFF;
    uint16_t formatted_offset = offset & mask;
    this->flags_n_offset = masked_flags_n_offset | formatted_offset;
}

/**
 * Sets the time to live (TTL) value for an IP packet.
 *
 * @param ttl The time to live value to be set.
 *
 * @returns None
 */
void IP_set_time_to_live(IP_Header_t* this, uint8_t time_to_live) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->time_to_live = time_to_live;
}

/**
 * Sets the protocol of an IP packet.
 *
 * @param packet The IP packet to modify.
 * @param protocol The protocol value to set.
 *
 * @returns None
 */
void IP_set_protocol(IP_Header_t* this, uint8_t protocol) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->protocol = protocol;
}

/**
 * Calculates and sets the checksum for an IP packet.
 *
 * @param packet The IP packet for which to calculate and set the checksum.
 *
 * @returns None
 */
void IP_set_checksum(IP_Header_t* this, uint16_t checksum) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->checksum = checksum;
}

/**
 * Sets the source IP address for an IP packet.
 *
 * @param address The source IP address to set.
 *
 * @returns None
 */
void IP_set_src_address(IP_Header_t* this, uint32_t src_address) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->src_address = src_address;
}

/**
 * Sets the destination IP address in the IP header.
 *
 * @param this A pointer to the IP header object.
 * @param dst_address The destination IP address to be set.
 *
 * @returns None
 *
 * @throws std::invalid_argument if the IP header object is NULL.
 */
void IP_set_dst_address(IP_Header_t* this, uint32_t dst_address) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->dst_address = dst_address;
}

/**
 * Updates the IP checksum of a packet.
 *
 * This function recalculates the IP checksum of a packet by updating the checksum field in the IP header.
 *
 * @param packet A pointer to the packet data.
 *
 * @returns None
 */
void IP_update_checksum(IP_Header_t* this) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(EXIT_FAILURE);
    }

    uint16_t ip_checksum = 0;
    // version, IHL, and type of service
    ip_checksum = ones_complement_add(ip_checksum, ((uint16_t) this->version_n_IHL << 8) | (uint16_t)this->type_of_service);
    // total length
    ip_checksum = ones_complement_add(ip_checksum, this->total_length);
    // id
    ip_checksum = ones_complement_add(ip_checksum, this->id);
    // flags and offset
    ip_checksum = ones_complement_add(ip_checksum, this->flags_n_offset);
    // time to live and protocol
    ip_checksum = ones_complement_add(ip_checksum, ((uint16_t)this->time_to_live << 8) | (uint16_t)this->protocol);
    // source address 
    uint16_t src_address_lower = this->src_address & 0xFFFF;
    uint16_t src_address_upper = (this->src_address >> 16) & 0xFFFF;
    ip_checksum = ones_complement_add(ip_checksum, src_address_lower);
    ip_checksum = ones_complement_add(ip_checksum, src_address_upper);
    // destination address
    uint16_t dst_address_lower = this->dst_address & 0xFFFF;
    uint16_t dst_address_upper = (this->dst_address >> 16) & 0xFFFF;
    ip_checksum = ones_complement_add(ip_checksum, dst_address_lower);
    ip_checksum = ones_complement_add(ip_checksum, dst_address_upper);

    // set one's complement
    this->checksum = ~ip_checksum;
}

/* TCP Segment */

/**
 * Sets the source port number for a TCP packet.
 *
 * @param packet The TCP packet to modify.
 * @param port The source port number to set.
 *
 * @returns None
 */
void TCP_set_src_port(TCP_Header_t* this, uint16_t src_port) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->src_port = src_port;
}

/**
 * Sets the destination port number for a TCP packet.
 *
 * @param port The destination port number to set.
 *
 * @returns None
 */
void TCP_set_dst_port(TCP_Header_t* this, uint16_t dst_port) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->dst_port = dst_port;
}

/**
 * Sets the sequence number for a TCP connection.
 *
 * @param sequence_num The sequence number to set.
 *
 * @returns None
 */
void TCP_set_sequence_num(TCP_Header_t* this, uint32_t seq_num) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->sequence_num = seq_num;
}

/**
 * Sets the acknowledgment number in a TCP packet.
 *
 * @param packet The TCP packet to modify.
 * @param ack_num The acknowledgment number to set.
 *
 * @returns None
 */
void TCP_set_ack_num(TCP_Header_t* this, uint32_t ack_num) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->ack_num = ack_num;
}

/**
 * Sets the offset value for a TCP connection.
 *
 * @param offset The offset value to be set.
 *
 * @returns None
 */
void TCP_set_offset(TCP_Header_t* this, uint8_t offset) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    offset = offset << 4;
    this->offset_n_reserved = this->offset_n_reserved | offset;
}

/**
 * Sets the reserved field in the TCP header.
 *
 * @param tcp_header A pointer to the TCP header structure.
 * @param reserved The value to set in the reserved field.
 *
 * @returns None
 */
void TCP_set_reserved(TCP_Header_t* this, uint8_t reserved) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    uint8_t mask = 0xF0;
    uint8_t masked_offset_n_reserved = this->offset_n_reserved & mask;
    this->offset_n_reserved = masked_offset_n_reserved | reserved;
}

/**
 * Sets the control bits for a TCP packet.
 *
 * This function is responsible for setting the control bits in a TCP packet header.
 * The control bits determine the behavior and characteristics of the TCP connection.
 *
 * @param packet The TCP packet to set the control bits for.
 * @param flags The flags to be passed to the control bits
 *
 * @returns None
 */
void TCP_set_control_bits(TCP_Header_t* this, uint8_t flags) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->control_bits = flags;
}

/**
 * Sets the TCP window size for a network connection.
 *
 * @param socket The socket descriptor of the network connection.
 * @param window_size The desired window size in bytes.
 *
 * @returns None
 */
void TCP_set_window(TCP_Header_t* this, uint16_t window) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->window = window;
}

/**
 * Sets the checksum field in the TCP header.
 *
 * @param tcp_header A pointer to the TCP header structure.
 *
 * @returns None
 */
void TCP_set_checksum(TCP_Header_t* this, uint16_t checksum) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->checksum = checksum;
}

/**
 * Sets the user-defined pointer for a TCP connection.
 *
 * @param connection The TCP connection object.
 * @param user_ptr The user-defined pointer to set.
 *
 * @returns None
 */
void TCP_set_ugent_ptr(TCP_Header_t* this, uint16_t urgent_ptr) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(-EINVAL);
    }
    this->urgent_ptr = urgent_ptr;
}

/**
 * Performs ones complement addition on two binary numbers.
 *
 * @param num1 The first binary number.
 * @param num2 The second binary number.
 *
 * @returns The result of the ones complement addition.
 */
uint16_t ones_complement_add(uint16_t a, uint16_t b) {
    uint32_t sum = a + b;  // Perform the addition, promoting to 32 bits to handle overflow
    sum = (sum & 0xFFFF) + (sum >> 16);  // Add any carry bits to the lower 16 bits
    return (uint16_t) sum;  // Discard any carry bits to obtain the final 16-bit sum
}

/**
 * Updates the TCP checksum field in the TCP header.
 *
 * @param tcp_header A pointer to the TCP header structure.
 * @param IP_segment
 *
 * @returns None
 */
void TCP_update_checksum(TCP_Header_t* this, IP_Header_t* IP_segment) {
    if (this == NULL) {
        perror("Object is NULL");
        exit(EXIT_FAILURE);
    }
    if (IP_segment == NULL) {
        perror("IP Segment is NULL");
        exit(EXIT_FAILURE);
    }

    const uint16_t TCP_LENGTH = 20;
    uint32_t tcp_checksum = 0;

    // protocol
    tcp_checksum = ones_complement_add(tcp_checksum, IP_segment->protocol);

    // source address
    uint16_t src_address_lower = IP_segment->src_address & 0xFFFF;
    uint16_t src_address_upper = (IP_segment->src_address >> 16) & 0xFFFF;
    tcp_checksum = ones_complement_add(tcp_checksum, src_address_lower);
    tcp_checksum = ones_complement_add(tcp_checksum, src_address_upper);

    // destination address
    uint16_t dst_address_lower = IP_segment->dst_address & 0xFFFF;
    uint16_t dst_address_upper = IP_segment->dst_address >> 16;
    tcp_checksum = ones_complement_add(tcp_checksum, dst_address_lower);
    tcp_checksum = ones_complement_add(tcp_checksum, dst_address_upper);

    // TCP Length
    tcp_checksum = ones_complement_add(tcp_checksum, TCP_LENGTH);

    // source port
    tcp_checksum = ones_complement_add(tcp_checksum, this->src_port);

    // destination port 
    tcp_checksum = ones_complement_add(tcp_checksum, this->dst_port);

    // sequence number
    uint16_t seq_lower = this->sequence_num & 0xFFFF;
    uint16_t seq_upper = (this->sequence_num >> 16) & 0xFFFF;
    tcp_checksum = ones_complement_add(tcp_checksum, seq_lower);
    tcp_checksum = ones_complement_add(tcp_checksum, seq_upper);

    // acknowledgement number
    uint16_t ack_lower = this->ack_num & 0xFFFF;
    uint16_t ack_upper = (this->ack_num >> 16) & 0xFFFF;
    tcp_checksum = ones_complement_add(tcp_checksum, ack_lower);
    tcp_checksum = ones_complement_add(tcp_checksum, ack_upper);

    // offset, reserved, and control bits
    tcp_checksum = ones_complement_add(tcp_checksum, ((uint16_t)this->offset_n_reserved << 8) | (uint16_t)this->control_bits);

    // window
    tcp_checksum = ones_complement_add(tcp_checksum, this->window);

    // urgent pointer 
    tcp_checksum = ones_complement_add(tcp_checksum, this->urgent_ptr);

    // set one's complement
    this->checksum = ~tcp_checksum;
}

/**
 * Converts an IP address from host byte order to network byte order.
 *
 * @param ip The IP address in host byte order.
 *
 * @returns The IP address in network byte order.
 */
void hton_ip(IP_Header_t *ip){
    ip->total_length = htons(ip->total_length);
    ip->id = htons(ip->id);
    ip->flags_n_offset = htons(ip->flags_n_offset);
    ip->checksum = htons(ip->checksum);
    ip->src_address = htonl(ip->src_address);
    ip->dst_address = htonl(ip->dst_address);
}

/**
 * Converts a 32-bit integer from host byte order to network byte order.
 *
 * @param host_int The 32-bit integer in host byte order.
 *
 * @returns The 32-bit integer in network byte order.
 */
void hton_tcp(TCP_Header_t *tcp){
    tcp->src_port = htons(tcp->src_port);
    tcp->dst_port = htons(tcp->dst_port);
    tcp->sequence_num = htonl(tcp->sequence_num);
    tcp->ack_num = htonl(tcp->ack_num);
    tcp->window = htons(tcp->window);
    tcp->checksum = htons(tcp->checksum);
    tcp->urgent_ptr = htons(tcp->urgent_ptr);
}
