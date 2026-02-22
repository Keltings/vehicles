from django.urls import path
from . import views

app_name = 'owner_portal'

urlpatterns = [
    # Authentication
    path('', views.owner_login, name='login'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('logout/', views.owner_logout, name='logout'),
    
    # Main pages
    path('dashboard/', views.owner_dashboard, name='dashboard'),
    path('availability/', views.parking_availability, name='availability'),
    path('history/', views.parking_history, name='history'),
    path('payments/', views.payment_history, name='payments'),
    
    # Downloads
    path('download-receipt/<int:vehicle_id>/', views.download_receipt, name='download_receipt'),
    path('download-summary/', views.download_summary, name='download_summary'),
]