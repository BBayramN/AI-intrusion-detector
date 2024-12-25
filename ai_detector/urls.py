from django.urls import path

from . import views

urlpatterns = [
    # path('', views.home,name='home'),
    # path('capture-data/', views.capture_data_view, name='capture_traffic'),
    path('task-status/<str:task_id>/', views.task_status, name='task_status'),
    path('ai-prediction/',views.predict,name="prediction")
]