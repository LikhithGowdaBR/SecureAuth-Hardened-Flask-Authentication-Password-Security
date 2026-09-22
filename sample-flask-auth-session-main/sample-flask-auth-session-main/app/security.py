# -*- encoding: utf-8 -*-
"""
Security module for tracking failed login attempts and triggering alerts
"""

from datetime import datetime, timedelta
from collections import defaultdict
from app.email_service import send_admin_alert

# In-memory storage for failed attempts
# Format: {ip_address: [(timestamp1, timestamp2, timestamp3, ...)]}
failed_attempts = defaultdict(list)

# In-memory storage for locked IPs
# Format: {ip_address: lockout_datetime}
locked_ips = {}

# Configuration
MAX_FAILED_ATTEMPTS = 3
ATTEMPT_WINDOW_MINUTES = 15  # Time window to count attempts
LOCKOUT_DURATION_MINUTES = 60  # Lock IP for 60 minutes after 3 failed attempts


def record_failed_attempt(ip_address):
    """
    Record a failed login attempt for an IP address.
    If threshold is reached, trigger admin alert and lock the IP.
    
    Args:
        ip_address (str): The IP address attempting login
    
    Returns:
        bool: True if alert was sent, False otherwise
    """
    now = datetime.now()
    
    # Add current attempt
    failed_attempts[ip_address].append(now)
    print(f"[SECURITY.PY] Recorded attempt for {ip_address}. Total attempts: {len(failed_attempts[ip_address])}")
    
    # Remove attempts older than the window
    window_start = now - timedelta(minutes=ATTEMPT_WINDOW_MINUTES)
    failed_attempts[ip_address] = [
        attempt for attempt in failed_attempts[ip_address]
        if attempt > window_start
    ]
    print(f"[SECURITY.PY] After cleanup: {len(failed_attempts[ip_address])} recent attempts (within {ATTEMPT_WINDOW_MINUTES} min)")
    
    # Check if threshold is reached
    current_count = len(failed_attempts[ip_address])
    print(f"[SECURITY.PY] Checking threshold: {current_count} >= {MAX_FAILED_ATTEMPTS}?")
    
    if current_count >= MAX_FAILED_ATTEMPTS:
        print(f"[SECURITY.PY] THRESHOLD REACHED! Locking IP and sending alert email...")
        
        # Lock the IP address
        lock_ip(ip_address)
        
        # Send alert to admin
        alert_sent = send_admin_alert(ip_address, failed_attempts[ip_address])
        
        # Reset counter for this IP
        failed_attempts[ip_address] = []
        
        print(f"[SECURITY.PY] Alert sent status: {alert_sent}. IP locked for {LOCKOUT_DURATION_MINUTES} minutes.")
        return True
    
    print(f"[SECURITY.PY] Threshold not reached yet ({current_count}/{MAX_FAILED_ATTEMPTS})")
    return False


def lock_ip(ip_address):
    """
    Lock an IP address from further login attempts
    
    Args:
        ip_address (str): The IP address to lock
    """
    lockout_time = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
    locked_ips[ip_address] = lockout_time
    print(f"[SECURITY.PY] IP {ip_address} locked until {lockout_time}")


def is_ip_locked(ip_address):
    """
    Check if an IP address is currently locked
    
    Args:
        ip_address (str): The IP address to check
    
    Returns:
        bool: True if IP is locked, False otherwise
    """
    if ip_address not in locked_ips:
        return False
    
    # Check if lockout has expired
    if datetime.now() > locked_ips[ip_address]:
        # Lockout expired, remove from locked list
        del locked_ips[ip_address]
        print(f"[SECURITY.PY] Lockout expired for IP {ip_address}")
        return False
    
    return True


def get_lockout_remaining_time(ip_address):
    """
    Get remaining lockout time for an IP in minutes
    
    Args:
        ip_address (str): The IP address to check
    
    Returns:
        int: Minutes remaining in lockout, or 0 if not locked
    """
    if ip_address not in locked_ips:
        return 0
    
    remaining = locked_ips[ip_address] - datetime.now()
    remaining_minutes = max(0, int(remaining.total_seconds() / 60))
    
    return remaining_minutes


def reset_failed_attempts(ip_address):
    """
    Reset failed attempts counter for an IP (after successful login)
    
    Args:
        ip_address (str): The IP address to reset
    """
    if ip_address in failed_attempts:
        failed_attempts[ip_address] = []


def get_failed_attempts_count(ip_address):
    """
    Get current count of failed attempts for an IP
    
    Args:
        ip_address (str): The IP address to check
    
    Returns:
        int: Number of failed attempts within the window
    """
    now = datetime.now()
    window_start = now - timedelta(minutes=ATTEMPT_WINDOW_MINUTES)
    
    if ip_address not in failed_attempts:
        return 0
    
    # Count only recent attempts
    recent_attempts = [
        attempt for attempt in failed_attempts[ip_address]
        if attempt > window_start
    ]
    
    return len(recent_attempts)
