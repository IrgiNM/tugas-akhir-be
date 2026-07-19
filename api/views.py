from django.shortcuts import render
from rest_framework import generics
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from .helpers import *
from .models import *
from .serializers import *
import pandas as pd
from rest_framework.views import APIView
from rest_framework.response import Response
from sklearn.cluster import KMeans
import numpy as np

from django.db import connection
from django.http import JsonResponse
from django.utils import timezone

# Create your views here.

# USER

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]

class GetListUserView(generics.ListAPIView):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

class GetCurrentUserView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

class DestroyUserView(generics.DestroyAPIView):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer


# PERMISSION

class CreatePermissionUser(generics.CreateAPIView):
    queryset = Permission.objects.all()
    permission_classes = (AllowAny,) 
    serializer_class = PermissionSerializer

class DestroyPermissionUser(generics.DestroyAPIView):
    queryset = Permission.objects.all()
    permission_classes = (AllowAny,) 
    serializer_class = PermissionSerializer

class GetListPermissionUser(generics.ListAPIView):
    serializer_class = PermissionSerializer
    permission_classes = (AllowAny,)

    def get_queryset(self):
        user_id = self.kwargs['user_id']
        return Permission.objects.filter(user_id=user_id)


# BACKUP

class DatabaseInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            table_info = []
            total_records = 0
            database_size = "-"
            backup_format = ".sql"

            with connection.cursor() as cursor:
                # Ambil seluruh nama tabel dari database aktif
                tables = connection.introspection.table_names(
                    cursor=cursor
                )

                for table in tables:
                    try:
                        # Otomatis:
                        # MySQL      -> `nama_tabel`
                        # PostgreSQL -> "nama_tabel"
                        quoted_table = connection.ops.quote_name(table)

                        cursor.execute(
                            f"SELECT COUNT(*) FROM {quoted_table}"
                        )

                        result = cursor.fetchone()
                        count = int(result[0]) if result else 0

                        total_records += count

                        table_info.append({
                            "table_name": table,
                            "records": count,
                        })

                    except Exception as table_error:
                        # Jangan menyembunyikan error sebagai angka 0
                        table_info.append({
                            "table_name": table,
                            "records": None,
                            "error": str(table_error),
                        })

                # Ukuran database MySQL
                if connection.vendor == "mysql":
                    cursor.execute("SELECT DATABASE()")
                    database_name = cursor.fetchone()[0]

                    cursor.execute(
                        """
                        SELECT COALESCE(
                            SUM(data_length + index_length),
                            0
                        )
                        FROM information_schema.tables
                        WHERE table_schema = %s
                        """,
                        [database_name],
                    )

                    size_bytes = int(cursor.fetchone()[0] or 0)
                    size_mb = size_bytes / (1024 * 1024)

                    database_size = f"{size_mb:.2f} MB"
                    backup_format = ".sql"

                # Ukuran database PostgreSQL
                elif connection.vendor == "postgresql":
                    cursor.execute(
                        """
                        SELECT pg_size_pretty(
                            pg_database_size(current_database())
                        )
                        """
                    )

                    database_size = cursor.fetchone()[0]
                    backup_format = ".dump"

            return JsonResponse({
                "status": "connected",
                "engine": connection.vendor,
                "total_tables": len(tables),
                "total_records": total_records,
                "database_size": database_size,
                "backup_format": backup_format,
                "checked_at": timezone.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "tables": table_info,
            })

        except Exception as error:
            return JsonResponse({
                "status": "disconnected",
                "error": str(error),
            }, status=500)


        




