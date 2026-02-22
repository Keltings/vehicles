from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from intelligence import views as intelligence_views


urlpatterns = [
    path('', intelligence_views.landing_page, name='landing'),  # ← ADD THIS
    path('admin/', admin.site.urls),
    path('intelligence/', include('intelligence.urls')),
    path('', lambda request: redirect('intelligence/', permanent=False)),
    path('my-parking/', include('owner_portal.urls')), 
]