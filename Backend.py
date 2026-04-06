import os
from openai import AzureOpenAI
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP
 
# ================================
# Azure OpenAI Client
# ================================
client = AzureOpenAI(
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    api_version=os.getenv("AZURE_OPENAI_API_VERSION"),
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
)
 
# ================================
# Flow Extraction (Optimized)
# ================================
def extract_flow_data(file_path):
    flows = {}
    MAX_PACKETS = 10000  # safety limit
 
    try:
        with PcapReader(file_path) as packets:
            count = 0
 
            for pkt in packets:
                if count > MAX_PACKETS:
                    break
                count += 1
 
                # Only process IP packets
                if not pkt.haslayer(IP):
                    continue
 
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
 
                # Protocol detection
                if pkt.haslayer(TCP):
                    protocol = "TCP"
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    protocol = "UDP"
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                else:
                    protocol = "OTHER"
                    src_port = 0
                    dst_port = 0
 
                # Bidirectional flow key
                flow_key = tuple(sorted([
                    (src_ip, src_port),
                    (dst_ip, dst_port)
                ])) + (protocol,)
 
                if flow_key not in flows:
                    flows[flow_key] = {
                        "packet_count": 0,
                        "total_bytes": 0,
                        "start_time": float(pkt.time),
                        "end_time": float(pkt.time),
                        "times": []
                    }
 
                flows[flow_key]["packet_count"] += 1
                flows[flow_key]["total_bytes"] += len(pkt)
                flows[flow_key]["end_time"] = float(pkt.time)
                flows[flow_key]["times"].append(float(pkt.time))
 
    except Exception as e:
        return [{"error": f"PCAP parsing failed: {str(e)}"}]
 
    if not flows:
        return []
 
    # ================================
    # Build Summary
    # ================================
    flow_summaries = []
 
    for key, data in flows.items():
        times = data["times"]
        duration = data["end_time"] - data["start_time"]
 
        delays = [t2 - t1 for t1, t2 in zip(times, times[1:])]
        avg_delay = sum(delays) / len(delays) if delays else 0
 
        summary = {
            "flow": f"{key[0]} ↔ {key[1]}",
            "protocol": key[2],
            "packet_count": data["packet_count"],
            "total_bytes": data["total_bytes"],
            "duration_sec": round(duration, 4),
            "avg_delay_sec": round(avg_delay, 6)
        }
 
        flow_summaries.append(summary)
 
    # Sort by packet count
    return sorted(flow_summaries, key=lambda x: x["packet_count"], reverse=True)[:10]
 
 
# ================================
# LLM Analysis
# ================================
def analyze_with_llm(flow_data):
    prompt = f"""
You are an expert network traffic analyst.
 
Analyze the following network flow summary.
 
DATA:
{flow_data}
 
Provide structured output:
 
Summary:
Issues:
Latency Observations:
Root Cause:
Recommendations:
 
Rules:
- Do NOT assume missing data
- If insufficient data, clearly say "insufficient evidence"
"""
 
    response = client.chat.completions.create(
        model=os.getenv("AZURE_OPENAI_DEPLOYMENT"),
        messages=[
            {"role": "system", "content": "You are a senior network security expert."},
            {"role": "user", "content": prompt}
        ]
    )
 
    return response.choices[0].message.content
 
 
# ================================
# Main Function
# ================================
def analyze_pcap(file_path):
    try:
        flow_data = extract_flow_data(file_path)
 
        if not flow_data:
            return {
                "status": "error",
                "analysis": "No valid network flows detected (possibly non-IP or malformed traffic)."
            }
 
        if isinstance(flow_data, list) and "error" in flow_data[0]:
            return {
                "status": "error",
                "analysis": flow_data[0]["error"]
            }
 
        result = analyze_with_llm(flow_data)
 
        return {
            "status": "success",
            "analysis": result,
            "flow_count": len(flow_data)
        }
 
    except Exception as e:
        return {
            "status": "error",
            "analysis": str(e)
        }
 
