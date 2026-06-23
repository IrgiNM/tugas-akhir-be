import requests
from django.utils.dateparse import parse_datetime
from django.conf import settings
from django.utils import timezone
from django.http import FileResponse
from datetime import timedelta

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from .services.watchguard_auth import get_access_token
from rest_framework.decorators import api_view

from .models import *
from .serializers import *
import numpy as np
import pandas as pd
import io
import ipaddress
import json
import os
import subprocess
import tempfile
from pathlib import Path
import csv
import posixpath
import re
import paramiko

from datetime import datetime, time, timedelta
from django.utils.dateparse import parse_date

from rest_framework.pagination import PageNumberPagination
from .services.watchguard_logs import fetch_logs
from .services.watchguard_get_syslog import fetch_logs_syslogs
from .services.syslog_dataset_service import export_syslog_dataset_to_csv
from .utils.vps_storage import upload_file_to_vps










# TOP REPORTS

class BaseTopReportView(APIView):
    view_name_value = None
    type_report = None

    def get(self, request):
        access_token = get_access_token()
        api_key = "aPoKpt9iSEwzR/fVC3vGd1INCbH5RUjKT0yUwcYz"
        account_id = "ACC-2693078"
        # waktu sekarang
        end_datetime = datetime.utcnow()
        # H-1
        start_datetime = end_datetime - timedelta(days=1)
        # format string
        start_date = start_datetime.strftime("%Y-%m-%dT%H:%M:%S")
        end_date = end_datetime.strftime("%Y-%m-%dT%H:%M:%S")
        # devices = "FB-12345"

        url = (
            f"https://api.jpn.cloud.watchguard.com"
            f"/rest/firebox/reports/v1/report/{account_id}/{self.type_report}"
        )

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "WatchGuard-API-Key": api_key,
            "Authorization": f"Bearer {access_token}"
        }

        params = {
            "view": self.view_name_value,
            "startDate": start_date,
            "endDate": end_date,
            # "devices": devices
        }

        # cek apakah data hari ini sudah ada
        already_exists = TopReport.objects.filter(
            view_name=self.view_name_value,
            fetched_at__date=end_datetime.date()
        ).exists()

        if already_exists:
            return Response({
                "status": "skip",
                "message": f"{self.view_name_value} already fetched today"
            })

        response = requests.get(
            url,
            headers=headers,
            params=params
        )

        if response.status_code != 200:
            return Response({
                "status": "error",
                "message": response.text
            }, status=response.status_code)

        json_data = response.json()
        report_data = json_data.get("data", [])
        saved_reports = []

        for item in report_data:
            report = TopReport.objects.create(
                view_name=self.view_name_value,
                name=item.get("name", ""),
                connections=int(item.get("connections", 0)),
                bytes=int(item.get("bytes", 0)),
                detail=item.get("detail", ""),
                raw_data=item
            )
            saved_reports.append(report)

        serializer = TopReportSerializer(
            saved_reports,
            many=True
        )

        return Response({
            "status": "success",
            "view": self.view_name_value,
            "total_saved": len(saved_reports),
            "data": serializer.data
        })
    
class TopBlockedCountriesView(BaseTopReportView):
    view_name_value = 'top_blocked_countries'
    type_report = 'security'
class TopBlockedAdvancedMalwareAptView(BaseTopReportView):
    view_name_value = 'top_blocked_advanced_malware_apt'
    type_report = 'security'
class TopBlockedBotnetSitesView(BaseTopReportView):
    view_name_value = 'top_blocked_botnet_sites'
    type_report = 'security'
class TopBlockedClientsView(BaseTopReportView):
    view_name_value = 'top_blocked_clients'
    type_report = 'security'
class TopBlockedDestinationsView(BaseTopReportView):
    view_name_value = 'top_blocked_destinations'
    type_report = 'security'
class TopBlockedUrlCategoriesView(BaseTopReportView):
    view_name_value = 'top_blocked_url_categories'
    type_report = 'security'
class TopBlockedApplicationsView(BaseTopReportView):
    view_name_value = 'top_blocked_applications'
    type_report = 'security'
class TopBlockedApplicationCategoriesView(BaseTopReportView):
    view_name_value = 'top_blocked_application_categories'
    type_report = 'security'
class TopBlockedProtocolsView(BaseTopReportView):
    view_name_value = 'top_blocked_protocols'
    type_report = 'security'
class TopBlockedAttacksView(BaseTopReportView):
    view_name_value = 'top_blocked_attacks'
    type_report = 'security'
class TopBlockedMalwareView(BaseTopReportView):
    view_name_value = 'top_blocked_malware'
    type_report = 'security'

class TopCountriesView(BaseTopReportView):
    view_name_value = 'top_countries'
    type_report = 'executive'
class TopZeroDayMalwareAptView(BaseTopReportView):
    view_name_value = 'top_zero_day_malware_apt'
    type_report = 'executive'
class TopClientsView(BaseTopReportView):
    view_name_value = 'top_clients'
    type_report = 'executive'
class TopDomainsView(BaseTopReportView):
    view_name_value = 'top_domains'
    type_report = 'executive'
class TopUrlCategoriesView(BaseTopReportView):
    view_name_value = 'top_url_categories'
    type_report = 'executive'
class TopDestinationsView(BaseTopReportView):
    view_name_value = 'top_destinations'
    type_report = 'executive'
class TopApplicationsView(BaseTopReportView):
    view_name_value = 'top_applications'
    type_report = 'executive'
class TopApplicationCategoriesView(BaseTopReportView):
    view_name_value = 'top_application_categories'
    type_report = 'executive'
class TopProtocolsView(BaseTopReportView):
    view_name_value = 'top_protocols'
    type_report = 'executive'

class TopReportListView(generics.ListAPIView):
    serializer_class = TopReportSerializer
    def get_queryset(self):
        queryset = TopReport.objects.all()
        # ambil query parameter
        date = self.request.query_params.get('date')
        month = self.request.query_params.get('month')
        year = self.request.query_params.get('year')
        # jika ada date -> filter berdasarkan tanggal lengkap
        if date:
            queryset = queryset.filter(
                fetched_at__date=date
            )
        # jika ada month -> filter berdasarkan bulan
        elif month:
            queryset = queryset.filter(
                fetched_at__month=month
            )
        # jika ada year -> filter berdasarkan tahun
        elif year:
            queryset = queryset.filter(
                fetched_at__year=year
            )
        # jika tidak ada parameter -> ambil semua data
        return queryset
    

# GEOLOCATION

class GeoLocationView(APIView):
    def get(self, request):
        ip = request.query_params.get("ip")
        if not ip:
            return Response(
                {"error": "IP is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            url = f"https://api.ip2location.io/?ip={ip}&key=380E59602AAC649C32D6AD6F9AE90961"
            res = requests.get(url, timeout=5)
            data = res.json()
            result = {
                "ip": data.get("ip"),
                "country_code": data.get("country_code"),
                "country_name": data.get("country_name"),
                "region_name": data.get("region_name"),
                "city_name": data.get("city_name"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "time_zone": data.get("time_zone"),
                "isp": data.get("isp"),
                "asn": data.get("asn"),
                "fraud_score": data.get("fraud_score", 0),
                "is_proxy": data.get("is_proxy", False),
                "country": data.get("country"),
            }
            return Response(result)
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# BACKUP DATABASE

class BackupDatabaseView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):

        temp_file = tempfile.NamedTemporaryFile(
            suffix=".dump",
            delete=False
        )

        env = os.environ.copy()
        env["PGPASSWORD"] = "112N4ZMU$"
        PG_DUMP_PATH = r"C:\Program Files\PostgreSQL\18\bin\pg_dump.exe"

        subprocess.run(
            [
                PG_DUMP_PATH,
                "-Fc",  # custom format
                "-h", "localhost",
                "-U", "postgres",
                "-d", "ta_project_irgi",
                "-f", temp_file.name
            ],
            env=env,
            check=True
        )

        return FileResponse(
            open(temp_file.name, "rb"),
            as_attachment=True,
            filename="backup_database.dump"
        )


# SYSLOG

class SyslogLogListView(APIView):
    def get(self, request):
        logs = SyslogLog.objects.all().order_by("-timestamp", "-id")

        log_type = request.query_params.get("log_type")
        action = request.query_params.get("action")
        src_ip = request.query_params.get("src_ip")
        dst_ip = request.query_params.get("dst_ip")
        msg_id = request.query_params.get("msg_id")

        date = request.query_params.get("date")
        month = request.query_params.get("month")
        year = request.query_params.get("year")

        if log_type:
            logs = logs.filter(log_type=log_type)

        if action:
            logs = logs.filter(action=action)

        if src_ip:
            logs = logs.filter(src_ip=src_ip)

        if dst_ip:
            logs = logs.filter(dst_ip=dst_ip)

        if msg_id:
            logs = logs.filter(msg_id=msg_id)

        if date:
            parsed_date = parse_date(date)

            if parsed_date:
                start_datetime = timezone.make_aware(
                    datetime.combine(parsed_date, time.min)
                )
                end_datetime = start_datetime + timedelta(days=1)

                logs = logs.filter(
                    timestamp__gte=start_datetime,
                    timestamp__lt=end_datetime,
                )

        if month:
            logs = logs.filter(timestamp__month=month)

        if year:
            logs = logs.filter(timestamp__year=year)

        serializer = SyslogLogListSerializer(logs, many=True)

        return Response(
            {
                "count": logs.count(),
                "data": serializer.data
            },
            status=status.HTTP_200_OK
        )

class SyslogLogDetailView(APIView):
    def get(self, request, pk):
        try:
            log = SyslogLog.objects.get(pk=pk)
        except SyslogLog.DoesNotExist:
            return Response(
                {"message": "Log tidak ditemukan"},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = SyslogLogSerializer(log)
        return Response(serializer.data)

class FetchSyslogLogView(APIView):
    def post(self, request):
        date = request.query_params.get("date")
        date_from = request.query_params.get("from")
        date_to = request.query_params.get("to")

        if date:
            date_from = date
            date_to = date

        result = fetch_logs_syslogs(
            date_from=date_from,
            date_to=date_to,
        )

        if result.get("error", 0) > 0:
            return Response(
                {
                    "message": "Fetch log gagal",
                    "result": result,
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response(
            {
                "message": "Fetch log selesai",
                "result": result,
            },
            status=status.HTTP_200_OK
        )


# DATASET

class ListSyslogDatasetView(APIView):
    def get(self, request):
        datasets = SyslogDataset.objects.all().order_by(
            "-dataset_date",
            "-updated_at"
        )

        serializer = SyslogDatasetSerializer(
            datasets,
            many=True,
            context={"request": request}
        )

        return Response({
            "message": "Daftar dataset berhasil diambil",
            "total": datasets.count(),
            "data": serializer.data,
        }, status=status.HTTP_200_OK)

class ExportSyslogDatasetView(APIView):
    def get(self, request):
        try:
            target_date = request.query_params.get("date")

            result = export_syslog_dataset_to_csv(
                target_date,
                generated_by="manual"
            )

            dataset = SyslogDataset.objects.get(id=result["id"])

            serializer = SyslogDatasetSerializer(
                dataset,
                context={"request": request}
            )

            return Response({
                "message": "Dataset syslog berhasil dibuat",
                **serializer.data,
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "message": "Gagal membuat dataset syslog",
                "error": str(e),
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DownloadSyslogDatasetView(APIView):
    def get(self, request, filename):
        try:
            dataset = SyslogDataset.objects.get(file_name=filename)
            file_path = Path(dataset.file_path)

            if not file_path.exists():
                return Response({
                    "message": "File dataset tidak ditemukan di storage"
                }, status=status.HTTP_404_NOT_FOUND)

            return FileResponse(
                open(file_path, "rb"),
                as_attachment=True,
                filename=dataset.file_name,
                content_type="text/csv",
            )

        except SyslogDataset.DoesNotExist:
            return Response({
                "message": "Data dataset tidak ditemukan di database"
            }, status=status.HTTP_404_NOT_FOUND)
        
class TestVpsUploadView(APIView):
    def get(self, request):
        try:
            file_name = f"test_railway_upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".csv",
                delete=False,
                newline="",
                encoding="utf-8",
            ) as temp_file:
                writer = csv.writer(temp_file)
                writer.writerow(["status", "message"])
                writer.writerow(["success", "Upload dari Django Railway ke VPS berhasil"])

                temp_file_path = temp_file.name

            file_url = upload_file_to_vps(temp_file_path, file_name)

            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)

            return Response(
                {
                    "message": "Upload ke VPS berhasil",
                    "file_name": file_name,
                    "file_url": file_url,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {
                    "message": "Upload ke VPS gagal",
                    "error": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )



# API DATASET

def check_dataset_api_key(request):
    api_key = request.headers.get("X-API-Key")

    if not settings.DATASET_API_KEY:
        return False

    return api_key == settings.DATASET_API_KEY


def dataset_response(dataset):
    return {
        "id": dataset.id,
        "date": dataset.dataset_date.strftime("%Y-%m-%d"),
        "file_name": dataset.file_name,
        "file_url": dataset.file_path,
        "total_rows": dataset.total_rows,
        "size_bytes": dataset.size_bytes,
        "size_mb": dataset.size_mb,
        "storage_type": dataset.storage_type,
        "generated_by": dataset.generated_by,
        "status": dataset.status,
        "created_at": dataset.created_at,
        "updated_at": dataset.updated_at,
    }


class ExternalDatasetListView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        if not check_dataset_api_key(request):
            return Response(
                {
                    "message": "API key tidak valid."
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        date_param = request.query_params.get("date")
        latest = request.query_params.get("latest")

        queryset = SyslogDataset.objects.filter(
            status="success"
        ).order_by("-dataset_date", "-updated_at")

        if date_param:
            dataset = queryset.filter(dataset_date=date_param).first()

            if not dataset:
                return Response(
                    {
                        "message": "Dataset tidak ditemukan.",
                        "date": date_param,
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

            return Response(dataset_response(dataset), status=status.HTTP_200_OK)

        if latest == "true":
            dataset = queryset.first()

            if not dataset:
                return Response(
                    {
                        "message": "Belum ada dataset."
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

            return Response(dataset_response(dataset), status=status.HTTP_200_OK)

        datasets = queryset[:30]

        return Response(
            {
                "message": "Daftar dataset berhasil diambil.",
                "total": len(datasets),
                "data": [dataset_response(dataset) for dataset in datasets],
            },
            status=status.HTTP_200_OK,
        )



def get_vps_private_key():
    private_key = settings.VPS_PRIVATE_KEY

    if not private_key:
        return None

    private_key = private_key.replace("\\n", "\n")
    key_file = io.StringIO(private_key)

    key_loaders = [
        paramiko.RSAKey,
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
        # paramiko.DSSKey,
    ]

    last_error = None

    for key_loader in key_loaders:
        try:
            key_file.seek(0)
            return key_loader.from_private_key(key_file)
        except Exception as e:
            last_error = e

    raise Exception(f"Gagal membaca private key VPS: {last_error}")


def get_vps_private_key():
    private_key = settings.VPS_PRIVATE_KEY

    if not private_key:
        return None

    private_key = private_key.replace("\\n", "\n")
    key_file = io.StringIO(private_key)

    key_loaders = [
        paramiko.RSAKey,
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
    ]

    last_error = None

    for key_loader in key_loaders:
        try:
            key_file.seek(0)
            return key_loader.from_private_key(key_file)
        except Exception as e:
            last_error = e

    raise Exception(f"Gagal membaca private key VPS: {last_error}")


class SyslogDatasetDataFromVPSAPIView(APIView):
    """
    Mengambil isi CSV dari VPS menggunakan SFTP.
    Bukan download file, tapi dikembalikan sebagai JSON.

    Contoh:
    /detection/syslog-dataset/data-vps/?date=2026-06-21
    /detection/syslog-dataset/data-vps/?date=2026-06-21&page=1&page_size=50
    """

    permission_classes = [AllowAny]

    def get(self, request):
        date = request.GET.get("date")
        page = request.GET.get("page", 1)
        page_size = request.GET.get("page_size", 50)

        if not date:
            return Response(
                {
                    "status": False,
                    "message": "Parameter date wajib diisi. Contoh: ?date=2026-06-21",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
            return Response(
                {
                    "status": False,
                    "message": "Format date tidak valid. Gunakan format YYYY-MM-DD.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            page = int(page)
            page_size = int(page_size)

            if page < 1:
                page = 1

            if page_size < 1:
                page_size = 50

            if page_size > 500:
                page_size = 500

        except ValueError:
            return Response(
                {
                    "status": False,
                    "message": "Parameter page dan page_size harus berupa angka.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not settings.VPS_HOST or not settings.VPS_USER:
            return Response(
                {
                    "status": False,
                    "message": "Konfigurasi VPS_HOST atau VPS_USER belum diatur.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        file_name = f"syslog_dataset_{date}.csv"
        remote_path = posixpath.join(settings.VPS_REMOTE_DIR, file_name)

        ssh = None
        sftp = None

        try:
            pkey = get_vps_private_key()

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            ssh.connect(
                hostname=settings.VPS_HOST,
                port=settings.VPS_PORT,
                username=settings.VPS_USER,
                pkey=pkey,
                timeout=15,
            )

            sftp = ssh.open_sftp()

            try:
                sftp.stat(remote_path)
            except FileNotFoundError:
                return Response(
                    {
                        "status": False,
                        "message": "File CSV tidak ditemukan di VPS.",
                        "file_name": file_name,
                        "remote_path": remote_path,
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

            rows = []

            with sftp.open(remote_path, mode="r") as remote_file:
                csv_text = remote_file.read().decode("utf-8-sig")
                csv_buffer = io.StringIO(csv_text)

                reader = csv.DictReader(csv_buffer)

                for row in reader:
                    rows.append(row)

            total_data = len(rows)
            total_page = (total_data + page_size - 1) // page_size

            start_index = (page - 1) * page_size
            end_index = start_index + page_size

            data = rows[start_index:end_index]

            return Response(
                {
                    "status": True,
                    "message": "Data CSV dari VPS berhasil diambil.",
                    "file_name": file_name,
                    "remote_path": remote_path,
                    "total_data": total_data,
                    "page": page,
                    "page_size": page_size,
                    "total_page": total_page,
                    "data": data,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {
                    "status": False,
                    "message": "Gagal mengambil data CSV dari VPS.",
                    "error": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        finally:
            if sftp:
                sftp.close()

            if ssh:
                ssh.close()


# def extract_date_from_filename(filename):
#     try:
#         # contoh: syslog_dataset_2026-06-20.csv
#         name = filename.replace(".csv", "")
#         return name.split("syslog_dataset_")[-1]
#     except Exception:
#         return "-"












