from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('', views.dashboard_view, name='dashboard'),
    
    # Analytics
    path('analytics/', views.analytics_overview, name='analytics_overview'),
    path('analytics/sites/', views.site_analytics, name='site_analytics'),
    path('analytics/time/', views.time_analytics, name='time_analytics'),
    path('analytics/vehicles/', views.vehicle_type_analytics, name='vehicle_type_analytics'),
    path('analytics/duration/', views.duration_analytics, name='duration_analytics'),
    
    # Vehicle Behavior
    path('vehicles/', views.vehicle_list, name='vehicle_list'),
    path('vehicles/search/', views.vehicle_search, name='vehicle_search'),
    
    # Alerts
    path('alerts/', views.alerts_center, name='alerts_center'),
    path('watchlist/', views.watchlist, name='watchlist'),
    path('api/vehicle/<str:plate_number>/', views.vehicle_detail_api, name='vehicle_detail_api'),
    path('alerts/resolve/<int:flag_id>/', views.resolve_alert, name='resolve_alert'),
    path('watchlist/remove/<int:flag_id>/', views.remove_from_watchlist, name='remove_from_watchlist'),
    path('api/route-vehicles/', views.route_vehicles_api, name='route_vehicles_api'),
]