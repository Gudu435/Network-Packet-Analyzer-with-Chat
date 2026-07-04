AI Packet Analyzer - Comprehensive Project Handoff

Version: 1.0
Project Owner: Subrat Patnaik
Primary Language: Python
Frontend: Streamlit
Packet Parsing: Scapy
AI Engine: Azure OpenAI GPT
Status: Production Prototype / Deployment Phase

1. Executive Summary

AI Packet Analyzer is an AI-powered network troubleshooting assistant that analyzes PCAP files and generates an expert-level Root Cause Analysis (RCA) similar to an experienced Wireshark engineer.

The objective is to reduce the time required for packet analysis from hours to minutes by combining:

High-speed packet parsing
Protocol intelligence
Flow analysis
Network statistics
AI-generated explanations

The application is designed for:

Network Engineers
TAC Engineers
Data Center Engineers
SD-WAN Engineers
Security Teams
Operations Teams
2. Business Problem

Traditional packet analysis requires:

Wireshark expertise
Manual inspection
Following TCP streams
Reading protocol details
Identifying anomalies manually

Large captures may take several hours.

The AI Packet Analyzer automates these tasks and produces a human-readable RCA.

3. Overall Workflow
User Uploads PCAP

        │

        ▼

Streamlit Upload Page

        │

        ▼

Validate File

        │

        ▼

Scapy PcapReader()

        │

        ▼

Extract Packet Metadata

        │

        ▼

Flow Identification

        │

        ▼

Protocol Statistics

        │

        ▼

TCP Analysis

        │

        ▼

UDP Analysis

        │

        ▼

DNS Analysis

        │

        ▼

HTTP Analysis

        │

        ▼

Generate JSON Summary

        │

        ▼

Azure OpenAI

        │

        ▼

AI Root Cause Analysis

        │

        ▼

Streamlit Dashboard
4. Technology Stack

Frontend

Streamlit

Backend

Python 3.10+

Packet Library

Scapy

LLM

Azure OpenAI

Libraries

streamlit

scapy

pandas

plotly

openai

python-dotenv

collections

statistics

datetime

json
5. Major Design Decision

Originally:

PyShark

Changed to

Scapy

Reason:

Faster
No dependency on tshark runtime
Better control
Lower memory usage
Streaming support through PcapReader
6. Packet Processing Engine

Instead of

rdpcap()

Use

PcapReader()

Reason

Loads one packet at a time

Consumes minimal RAM

Supports huge captures

Pseudo

for packet in PcapReader(file):

    parse()

    update statistics

    discard packet
7. Current Features
Upload PCAP

Supports

.pcap

.pcapng

Maximum upload

150 MB

(Current configurable.)

8. Packet Statistics

Collected

Total packets

Total bytes

Capture duration

Average packet size

Packet rate

Bandwidth

Unique hosts

Unique conversations

Top talkers

9. Layer Analysis

L2

MAC addresses

Broadcast

Multicast

Duplicate frames

ARP

VLAN

L3

IPv4

IPv6

TTL

Fragmentation

DF/MF flags

Routing anomalies

L4

TCP

UDP

ICMP

10. TCP Analysis

Implemented

TCP Handshake

Retransmissions

Duplicate ACK

TCP Flags

SYN

FIN

RST

ACK

Window Size

Zero Window

Window Scaling

Connection Count

Connection Failures

Missing ACK

Half-open Connections

Unexpected Reset

11. UDP Analysis

Implemented

Packet count

Conversation count

Top UDP ports

Loss estimation (heuristic)

Burst detection

High-rate UDP

Future

Jitter

Latency estimation

RTP awareness

12. DNS Analysis

Implemented

Queries

Responses

NXDOMAIN

Failed lookups

Most queried domains

Slow DNS

Future

DNSSEC

EDNS

13. HTTP Analysis

Implemented

HTTP methods

Status codes

Request count

Future

URL extraction

Host statistics

REST API analysis

14. TLS Analysis

Planned

TLS version

Cipher Suite

Certificate Issues

Handshake failures

15. ICMP

Implemented

Echo Request

Echo Reply

Destination Unreachable

TTL exceeded

16. AI Analysis

Current LLM

Azure OpenAI

Prompt contains

Network statistics

TCP metrics

UDP metrics

DNS metrics

Protocol distribution

Host statistics

Anomalies

The model returns

Executive Summary

Observed Problems

Likely Root Cause

Impact

Recommendations

Confidence
17. Prompt Engineering

Prompt instructs model to behave like

Senior Network TAC Engineer

Cisco Expert

Wireshark Expert

Network Performance Engineer

Model must avoid hallucinations.

Must only infer from evidence.

18. Expected JSON Output
{

summary

root_cause

evidence

affected_hosts

protocols

severity

recommendations

confidence

}
19. Streamlit Dashboard

Contains

Upload button

Analyze button

Progress bar

Spinner

Summary cards

AI Report

Chat interface

Reset button

20. Performance Optimizations

Already Implemented

✔ Streaming packet reading

✔ Avoid rdpcap()

✔ Efficient dictionaries

✔ Flow aggregation

✔ Reduced memory footprint

21. Current Deployment Issue

Deployment team reported:

Hardcoded PCAP

↓

Works

Uploaded Large PCAP

↓

Fails

Likely reasons

Memory pressure

Upload timeout

Temporary storage limits

Blocking UI thread

Reverse proxy limits

22. Proposed Solution

Instead of

Upload

↓

Analyze

Use

Upload

↓

Save File

↓

Background Queue

↓

Worker

↓

Progress Status

↓

Download Report

Benefits

No timeout

Supports GB captures

Scalable

Cloud friendly

23. Future Large PCAP Strategy

Chunk processing

Reader

↓

10,000 packets

↓

Analyze

↓

Discard

↓

Next chunk

Never keep all packets in RAM.

24. Error Handling

Handle

Corrupt PCAP

Empty PCAP

Unsupported protocols

Timeout

MemoryError

Azure API failure

Invalid upload

25. Logging

Log

Upload start

Upload end

Packet count

Flow count

LLM request

LLM response time

Exceptions

26. Future Enhancements
Protocols

BGP

OSPF

MPLS

VXLAN

GRE

LACP

STP

LLDP

CDP

SIP

RTP

NTP

DHCP

TCP Intelligence

RTT

Congestion Window

SACK

Fast Retransmit

Out-of-order

Lost Segments

Security

Port Scan

DDoS

ARP Spoof

DNS Tunneling

TCP Scan

SYN Flood

AI

Chat with PCAP

Compare Two PCAPs

Incident Timeline

Natural Language Queries

Packet Search

27. Scalability Vision

Future architecture

Browser

↓

Streamlit

↓

REST API

↓

Redis Queue

↓

Worker Pool

↓

Packet Engine

↓

Azure OpenAI

↓

Database

↓

Reports
28. Testing

Test cases

Small PCAP

Medium PCAP

Large PCAP

Malformed PCAP

No TCP

Only UDP

DNS only

Millions of packets

Mixed protocols

29. Known Limitations

Current version

Single worker

Synchronous analysis

Entire report waits for completion

No persistent database

No authentication

No distributed processing

30. Production Roadmap

Phase 1

✔ Packet parsing

✔ Dashboard

✔ AI summary

✔ Azure integration

Phase 2

Background jobs

Queue

Progress tracking

Caching

Better charts

Phase 3

Enterprise deployment

Authentication

REST APIs

Role-based access

Database

Phase 4

Distributed packet engine

Multi-worker processing

GPU inference

Cloud-native deployment

31. Current Blocker

The deployment team observed:

Hardcoded PCAP files analyze successfully.
Large uploaded PCAP files fail during analysis.

The recommended investigation order is:

Confirm the uploaded file is fully written to disk before analysis starts.
Verify that the uploaded file path (not the in-memory upload object) is passed to PcapReader.
Check for reverse proxy or web server upload size/time limits if applicable.
Monitor memory consumption during parsing.
Move analysis into a background worker to avoid request or UI timeouts.
Instrument the pipeline with detailed logging to identify the exact failure point.
32. Lessons Learned
Streaming packet processing is essential for scalability.
PcapReader is significantly more memory-efficient than rdpcap for large captures.
Separating packet extraction from AI analysis produces cleaner, more reliable prompts.
Structured JSON output from the LLM is easier to validate and render than free-form text.
Performance bottlenecks often stem from upload and processing architecture rather than the parsing library itself.
33. Handoff Notes for the Next Engineer or LLM

Key assumptions to preserve:

Scapy is the preferred parsing library.
The analyzer should remain evidence-driven; AI should not invent findings unsupported by packet data.
Packet processing should continue to use a streaming architecture.
The application should be designed to handle progressively larger PCAP files without linear memory growth.
Future enhancements should build on modular protocol analyzers rather than a monolithic parser.
