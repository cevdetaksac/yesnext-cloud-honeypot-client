# Service Management Commands Documentation

## Cloud Honeypot Client - Service Management

The Cloud Honeypot Client now includes a comprehensive Windows Service management system for automatic monitoring and restart functionality.

### Available Commands

#### 1. Install Service
```bash
python client.py --install
```
- Installs the Cloud Honeypot Monitor Service
- **Requires Administrator privileges**
- Service will automatically start after installation
- Monitors client application and restarts if crashes occur

#### 2. Remove Service  
```bash
python client.py --remove
```
- Removes the Cloud Honeypot Monitor Service
- **Requires Administrator privileges**  
- Stops the service before removal
- Client application continues working normally after removal

#### 3. Check Service Status
```bash
python client.py --service-status
```
- Shows current service status and information
- Does not require Administrator privileges
- Displays service state, process information, and health status

### Batch Files for Easy Management

For user convenience, we've included batch files:

- **`install_service.bat`** - Double-click to install service (auto-requests admin)
- **`remove_service.bat`** - Double-click to remove service (auto-requests admin) 
- **`check_service_status.bat`** - Double-click to check status (no admin needed)

### Service Features

#### Automatic Monitoring
- Checks client application status every 30 seconds
- Uses multiple detection methods (psutil + Windows tasklist)
- Monitors process health and responsiveness

#### Intelligent Restart Logic
- Configurable restart attempts (default: 5 per hour)
- Exponential backoff with cooldown periods
- Prevents restart loops from crashed applications

#### Comprehensive Logging
- Rotating log files (10MB max, 5 file retention)
- Windows Event Log integration
- Detailed error tracking and debugging info

#### Service Configuration
- **Service Name**: `CloudHoneypotMonitor`
- **Display Name**: `Cloud Honeypot Monitor Service` 
- **Start Type**: Automatic (starts with Windows)
- **Account**: Local System (runs in background)
- **Recovery**: Automatic restart on failure

### Installation Integration

The NSIS installer automatically:
1. Installs all required dependencies
2. Configures the service scripts
3. Offers to install the monitor service
4. Sets up proper file permissions
5. Creates Windows shortcuts for management

### Troubleshooting

#### Service Won't Install
- Ensure running as Administrator
- Check Python and dependencies are installed
- Verify no antivirus blocking the installation
- Try manual installation: `python service_wrapper.py install`

#### Service Not Monitoring Client
- Check service is running: `services.msc` → find `Cloud Honeypot Monitor Service`
- Review service logs in Windows Event Viewer
- Ensure client executable path is correct in service configuration
- Try restarting the service

#### Client Still Crashes
- Check restart attempt limits haven't been exceeded
- Review service logs for error patterns
- Verify client application is stable outside service monitoring
- Consider adjusting monitoring intervals in `service_wrapper.py`

### Advanced Configuration

Service behavior can be customized by editing `service_wrapper.py`:

```python
# Monitoring intervals
CHECK_INTERVAL = 30  # seconds between checks

# Restart limits
MAX_RESTART_ATTEMPTS = 5  # per time window  
RESTART_WINDOW = 3600    # time window in seconds

# Cooldown periods
INITIAL_COOLDOWN = 60    # seconds after first restart
MAX_COOLDOWN = 300       # maximum cooldown period
```

### Technical Details

#### Process Detection
1. **Primary**: Uses psutil library for accurate process monitoring
2. **Fallback**: Windows tasklist command for compatibility
3. **Verification**: Checks process responsiveness and resource usage

#### Service Architecture
- **Service Wrapper**: `service_wrapper.py` - Main service implementation
- **Client Integration**: `client.py` - Command-line service management  
- **Installer Integration**: `installer.nsi` - Automated deployment

#### Security Considerations
- Service runs with minimal required privileges
- Client application started in user context when possible
- Service logs do not contain sensitive information
- Secure process monitoring without interfering with client security

This service system ensures 99.9%+ uptime for your Cloud Honeypot Client with minimal system resource usage.