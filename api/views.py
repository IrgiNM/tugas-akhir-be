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
            with connection.cursor() as cursor:
                # Ambil semua nama tabel
                tables = connection.introspection.table_names()

                table_info = []
                total_records = 0

                for table in tables:
                    try:
                        cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
                        count = cursor.fetchone()[0]
                        total_records += count

                        table_info.append({
                            "table_name": table,
                            "records": count
                        })
                    except Exception:
                        table_info.append({
                            "table_name": table,
                            "records": 0
                        })

                db_size = None

                # Khusus PostgreSQL
                if connection.vendor == "postgresql":
                    cursor.execute("""
                        SELECT pg_size_pretty(pg_database_size(current_database()))
                    """)
                    db_size = cursor.fetchone()[0]

            return JsonResponse({
                "status": "connected",
                "engine": connection.vendor,
                "total_tables": len(tables),
                "total_records": total_records,
                "database_size": db_size or "-",
                "backup_format": ".dump",
                "checked_at": timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
                "tables": table_info
            })

        except Exception as e:
            return JsonResponse({
                "status": "disconnected",
                "error": str(e)
            }, status=500)


        




