from rest_framework import serializers
from .models import *
from pathlib import Path
from django.urls import reverse


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


class SyslogDatasetSerializer(serializers.ModelSerializer):
    date = serializers.DateField(source="dataset_date", read_only=True)
    download_url = serializers.SerializerMethodField()
    file_exists = serializers.SerializerMethodField()

    class Meta:
        model = SyslogDataset
        fields = [
            "id",
            "file_name",
            "file_path",
            "date",
            "total_rows",
            "size_bytes",
            "size_mb",
            "storage_type",
            "generated_by",
            "status",
            "file_exists",
            "download_url",
            "created_at",
            "updated_at",
        ]

    def get_download_url(self, obj):
        request = self.context.get("request")

        if not request:
            return None

        url = reverse(
            "download-syslog-dataset",
            kwargs={"filename": obj.file_name}
        )

        return request.build_absolute_uri(url)

    def get_file_exists(self, obj):
        return Path(obj.file_path).exists()




