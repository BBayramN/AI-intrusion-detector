from django.urls import path

from . import views

urlpatterns = [
    path('', views.home),
    path('capture-traffic/', views.capture_traffic, name='capture_traffic'),
]