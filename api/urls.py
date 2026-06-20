from django.urls import path
from .views import *
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [
    path('login/', obtain_auth_token, name='api_login'),
    path('user/create/', RegisterView.as_view(), name='api_create_user'),
    path('user/get/', GetListUserView.as_view(), name='api_get_list_user'),
    path('user/me/', GetCurrentUserView.as_view(), name='api_get_user_me'),
    path('user/delete/<int:pk>/', DestroyUserView.as_view(), name='api_delete_user'),

    # path('networkTraffic/create/', CreateListNetworkTrafficView.as_view(), name='create-list-network-traffic'),
    # path('networkTraffic/list/', GetListNetworkTrafficView.as_view(), name='get-list-network-traffic'),
    
    # path('logRaw/create/', CreateListLogRawView.as_view(), name='create-list-log-raw'),
    # path('logRaw/list/', GetListLogRawView.as_view(), name='get-list-log-raw'),

    path('permission/create/', CreatePermissionUser.as_view(), name='create-permission-user'),
    path('permission/list/<int:user_id>/', GetListPermissionUser.as_view(), name='get-list-permission-user'),
    path('permission/delete/<int:pk>/', DestroyPermissionUser.as_view(), name='delete-permission-user'),

    path('database-info/', DatabaseInfoView.as_view(), name='database-info'),

    # path('uploadCSV/', UploadCSVView.as_view(), name='upload_csv'),
]
