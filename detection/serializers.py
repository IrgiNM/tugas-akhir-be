from rest_framework import serializers
from .models import *


class TopReportSerializer(serializers.ModelSerializer):
    view_display = serializers.SerializerMethodField()
    formatted_bytes = serializers.SerializerMethodField()
    class Meta:
        model = TopReport
        fields = [
            'id',
            'view_name',
            'view_display',
            'name',
            'connections',
            'bytes',
            'formatted_bytes',
            'detail',
            'fetched_at',
            'raw_data',
        ]

    def get_view_display(self, obj):
        return obj.get_view_name_display()
    
    def get_formatted_bytes(self, obj):
        size = obj.bytes
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"
    

    
class SyslogLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = SyslogLog
        fields = "__all__"

class SyslogLogListSerializer(serializers.ModelSerializer):
    class Meta:
        model = SyslogLog
        fields = [
            "id",
            "timestamp",
            "device_name",
            "log_type",
            "msg_id",
            "action",
            "from_zone",
            "to_zone",
            "protocol",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "geo_src",
            "geo_dst",
            "policy",
            "message",
            "app_name",
            "cat_name",
            "dstname",
            "extra_data",
            "created_at",
        ]