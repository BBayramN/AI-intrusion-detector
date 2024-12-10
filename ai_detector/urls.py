from django.urls import path

from . import views

urlpatterns = [
    # path('', views.home,name='home'),
    path('capture-data/', views.capture_data, name='capture_traffic'),
]