from django.db import models
import uuid


# TOP REPORTS

class TopReport(models.Model):
    VIEW_CHOICES = [
        ('top_blocked_countries', 'Top Countries Blocked by Geolocation'),
        ('top_blocked_advanced_malware_apt', 'Top Malware Blocked by APT Blocker'),
        ('top_blocked_botnet_sites', 'Top Botnet Sites Blocked by Botnet Detection'),
        ('top_blocked_clients', 'Top Clients Blocked by the Firebox'),
        ('top_blocked_destinations', 'Top Destinations Blocked by the Firebox'),
        ('top_blocked_url_categories', 'Top URL Categories Blocked by WebBlocker'),
        ('top_blocked_applications', 'Top Applications Blocked by Application Control'),
        ('top_blocked_application_categories', 'Top Application Categories Blocked by Application Control'),
        ('top_blocked_protocols', 'Top Network Protocols Blocked by the Firebox'),
        ('top_blocked_attacks', 'Top Attacks Blocked by the Firebox'),
        ('top_blocked_malware', 'Top Malware Blocked by the Firebox'),
    ]
    view_name = models.CharField(max_length=100, choices=VIEW_CHOICES)
    name = models.CharField(max_length=255)
    connections = models.IntegerField(default=0)
    bytes = models.BigIntegerField(default=0)
    detail = models.TextField(blank=True, null=True)
    fetched_at = models.DateTimeField(auto_now_add=True)
    raw_data = models.JSONField(default=dict)
    class Meta:
        ordering = ['-connections']
    def __str__(self):
        return f"{self.view_name} - {self.name}"
    

# SYSLOG

class SyslogLog(models.Model):
    LOG_TYPE_CHOICES = [
        ("firewall", "Firewall"),
        ("https-proxy", "HTTPS Proxy"),
        ("http-proxy", "HTTP Proxy"),
        ("tcp-udp-proxy", "TCP UDP Proxy"),
        ("link-mon", "Link Monitor"),
        ("loggerd", "Loggerd"),
        ("unknown", "Unknown"),
    ]

    ACTION_CHOICES = [
        ("Allow", "Allow"),
        ("Deny", "Deny"),
        ("Block", "Block"),
        ("Drop", "Drop"),
        ("Unknown", "Unknown"),
    ]

    # field umum
    timestamp = models.DateTimeField(null=True, blank=True)
    device_name = models.CharField(max_length=100, null=True, blank=True)
    device_id = models.CharField(max_length=100, null=True, blank=True)
    device_time = models.DateTimeField(null=True, blank=True)

    # jenis log
    log_type = models.CharField(
        max_length=50,
        choices=LOG_TYPE_CHOICES,
        default="unknown"
    )

    process_id = models.IntegerField(null=True, blank=True)
    msg_id = models.CharField(max_length=50, null=True, blank=True)

    # field traffic umum
    action = models.CharField(
        max_length=50,
        choices=ACTION_CHOICES,
        default="Unknown"
    )
    from_zone = models.CharField(max_length=100, null=True, blank=True)
    to_zone = models.CharField(max_length=100, null=True, blank=True)

    protocol = models.CharField(max_length=20, null=True, blank=True)

    src_ip = models.GenericIPAddressField(null=True, blank=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True)

    src_port = models.IntegerField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)

    geo_src = models.CharField(max_length=10, null=True, blank=True)
    geo_dst = models.CharField(max_length=10, null=True, blank=True)

    policy = models.CharField(max_length=255, null=True, blank=True)
    message = models.TextField(null=True, blank=True)

    # field yang sering muncul tapi tidak selalu ada
    app_name = models.CharField(max_length=255, null=True, blank=True)
    cat_name = models.CharField(max_length=255, null=True, blank=True)
    dstname = models.CharField(max_length=255, null=True, blank=True)

    # ini yang penting untuk field baru
    extra_data = models.JSONField(default=dict, blank=True)

    # log asli
    raw_log = models.TextField(unique=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["timestamp"]),
            models.Index(fields=["log_type"]),
            models.Index(fields=["action"]),
            models.Index(fields=["src_ip"]),
            models.Index(fields=["dst_ip"]),
            models.Index(fields=["msg_id"]),
        ]

    def __str__(self):
        return f"{self.timestamp} - {self.log_type} - {self.action}"










