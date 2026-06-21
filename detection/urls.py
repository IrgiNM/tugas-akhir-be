from django.urls import path
from .views import *
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [

    path('top-reports/',TopReportListView.as_view()),
    path('top-blocked-countries/', TopBlockedCountriesView.as_view()),
    path('top-blocked-advanced-malware-apt/', TopBlockedAdvancedMalwareAptView.as_view()),
    path('top-blocked-botnet-sites/', TopBlockedBotnetSitesView.as_view()),
    path('top-blocked-clients/', TopBlockedClientsView.as_view()),
    path('top-blocked-destinations/', TopBlockedDestinationsView.as_view()),
    path('top-blocked-url-categories/', TopBlockedUrlCategoriesView.as_view()),
    path('top-blocked-applications/', TopBlockedApplicationsView.as_view()),
    path('top-blocked-application-categories/', TopBlockedApplicationCategoriesView.as_view()),
    path('top-blocked-protocols/', TopBlockedProtocolsView.as_view()),
    path('top-blocked-attacks/', TopBlockedAttacksView.as_view()),
    path('top-blocked-malware/', TopBlockedMalwareView.as_view()),

    path('top-countries/', TopCountriesView.as_view()),
    path('top-zero-day-malware-apt/', TopZeroDayMalwareAptView.as_view()),
    path('top-clients/', TopClientsView.as_view()),
    path('top-domains/', TopDomainsView.as_view()),
    path('top-url-categories/', TopUrlCategoriesView.as_view()),
    path('top-destinations/', TopDestinationsView.as_view()),
    path('top-applications/', TopApplicationsView.as_view()),
    path('top-application-categories/', TopApplicationCategoriesView.as_view()),
    path('top-protocols/', TopProtocolsView.as_view()),

    path("geo/", GeoLocationView.as_view()),

    path("backup/", BackupDatabaseView.as_view()),

    path("syslog-logs/", SyslogLogListView.as_view()),
    path("syslog-logs/<int:pk>/", SyslogLogDetailView.as_view()),
    path("syslog-logs/fetch/", FetchSyslogLogView.as_view()),

    path(
        "syslog-dataset/list/",
        ListSyslogDatasetView.as_view(),
        name="list-syslog-dataset",
    ),
    path(
        "syslog-dataset/export/",
        ExportSyslogDatasetView.as_view(),
        name="export-syslog-dataset",
    ),
    path(
        "syslog-dataset/download/<str:filename>/",
        DownloadSyslogDatasetView.as_view(),
        name="download-syslog-dataset",
    ),

    path("test-vps-upload/", TestVpsUploadView.as_view(), name="test-vps-upload"),

    path("external/datasets/", ExternalDatasetListView.as_view(), name="external-datasets"),

]
