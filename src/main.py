import json


def load_packets(file_path):
    with open(file_path, "r") as file:
        packets = json.load(file)
    return packets


def create_flow_key(packet):
    return (
        packet["src_ip"],
        packet["dst_ip"],
        packet["protocol"],
        packet["src_port"],
        packet["dst_port"],
    )


def get_service_name(port):
    common_ports = {
        21: "FTP",
        22: "SSH",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        5432: "PostgreSQL",
    }

    return common_ports.get(port, "Unknown")


def group_packets_into_flows(packets):
    flows = {}

    for packet in packets:
        flow_key = create_flow_key(packet)

        if flow_key not in flows:
            flows[flow_key] = {
                "src_ip": packet["src_ip"],
                "dst_ip": packet["dst_ip"],
                "protocol": packet["protocol"],
                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"],
                "service": get_service_name(packet["dst_port"]),
                "packet_count": 0,
                "total_size": 0,
            }

        flows[flow_key]["packet_count"] += 1
        flows[flow_key]["total_size"] += packet["size"]

    return list(flows.values())


def print_flows(flows):
    print("\nNetwork Flows")
    print("-" * 80)

    for flow in flows:
        print(
            f'{flow["src_ip"]}:{flow["src_port"]} -> '
            f'{flow["dst_ip"]}:{flow["dst_port"]} '
            f'({flow["protocol"]}) | '
            f'Service: {flow["service"]} | '
            f'Packets: {flow["packet_count"]} | '
            f'Total Size: {flow["total_size"]} bytes'
        )


def main():
    packets = load_packets("data/sample_packets.json")
    flows = group_packets_into_flows(packets)
    print_flows(flows)


if __name__ == "__main__":
    main()
