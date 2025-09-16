# PXE Boot / Network Boot Feature

## Overview
The PXE Boot feature enables automated secure wiping of 1000+ devices simultaneously through network booting. This is ideal for enterprise environments, data centers, and mass device decommissioning.

## Key Features

### ✅ Mass Device Support
- Wipe 1000+ devices simultaneously
- Fully automated process
- No manual intervention required per device

### ✅ Works with Corrupted/Locked Systems
- Bypasses OS-level restrictions
- Works even if client OS is corrupted
- No dependency on client system state

### ✅ Automated Certificate Collection
- Each device generates signed certificates
- Automatic collection on central server
- Tamper-proof verification system

### ✅ Real-time Monitoring
- Live client status tracking
- Progress monitoring per device
- MAC address and IP identification

## How It Works

### 1. Server Setup
- Configure PXE server on central machine
- Set DHCP range and network parameters
- Choose wipe mode (Quick, DoD, Gutmann)
- Enable auto-shutdown option

### 2. Client Configuration
- Set all client laptops to boot from network (PXE)
- Connect clients to same network as server
- Power on devices - they boot automatically

### 3. Automated Process
- PXE server sends bootable OS + wiping script
- Each laptop executes wipe automatically
- Progress tracked in real-time
- Certificates generated and collected
- Optional auto-shutdown after completion

## Configuration Options

### Network Settings
- **Server IP**: IP address of the PXE server
- **DHCP Range**: IP range for client devices
- **Gateway**: Network gateway address
- **DNS Server**: DNS server for network resolution

### Wipe Settings
- **Quick Wipe**: Fast single-pass overwrite
- **DoD 5220.22-M**: Military standard 3-pass wipe
- **Gutmann**: 35-pass secure wipe method
- **Auto-shutdown**: Automatically power off after completion

### Security Features
- **Certificate Generation**: Cryptographic proof of wipe completion
- **Hash Verification**: Tamper-proof certificate validation
- **Device Identification**: MAC address and hardware ID tracking
- **Timestamp Verification**: Precise completion time recording

## Client Status Monitoring

The PXE server provides real-time monitoring of all connected clients:

- **MAC Address**: Hardware identifier
- **IP Address**: Network address assigned
- **Status**: Current operation (booting, wiping, completed, failed)
- **Progress**: Percentage completion
- **Last Update**: Timestamp of last status report

## Use Cases

### Enterprise IT
- Mass laptop refresh programs
- Employee device returns
- Hardware lifecycle management

### Data Centers
- Server decommissioning
- Storage device retirement
- Compliance requirements

### Educational Institutions
- Student device management
- Lab computer maintenance
- Semester-end cleanups

### Government/Military
- Classified data destruction
- Security clearance requirements
- Audit compliance

## Technical Requirements

### Server Requirements
- Windows/Linux system with network access
- Sufficient bandwidth for client count
- Administrative privileges for network services
- Storage space for certificates

### Network Requirements
- Isolated network segment (recommended)
- DHCP server capability
- TFTP server support
- HTTP server for file distribution

### Client Requirements
- PXE boot capability (most modern systems)
- Network interface card
- Connection to PXE server network

## Security Considerations

### Network Isolation
- Use dedicated network segment
- Isolate from production networks
- Control physical access to network

### Certificate Management
- Secure certificate storage
- Regular backup of certificates
- Access control to certificate files

### Audit Trail
- Complete operation logging
- Device identification records
- Timestamp verification

## Getting Started

1. **Open Secure Wipe Application**
2. **Click "PXE Network Boot" in sidebar**
3. **Configure server settings**
4. **Start PXE server**
5. **Set client devices to PXE boot**
6. **Power on client devices**
7. **Monitor progress in real-time**
8. **Collect certificates when complete**

## Troubleshooting

### Common Issues
- **Clients not booting**: Check PXE boot order in BIOS
- **Network connectivity**: Verify DHCP configuration
- **Server not starting**: Check firewall settings
- **Certificate collection**: Verify HTTP server accessibility

### Support
For technical support and advanced configuration, refer to the main application documentation or contact system administrators.

---

**Note**: This feature requires administrative privileges and proper network configuration. Test in a controlled environment before production deployment.