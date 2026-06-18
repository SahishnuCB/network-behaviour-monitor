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
            f'Packets: {flow["packet_count"]} | '
            f'Total Size: {flow["total_size"]} bytes'
        )


def main():
    packets = load_packets("data/sample_packets.json")
    flows = group_packets_into_flows(packets)
    print_flows(flows)


if __name__ == "__main__":
    main()
