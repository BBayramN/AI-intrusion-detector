from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('/home', views.homepage, name='homepage'), 
   # path('admin/', admin.site.urls),
    path('signup/', views.signup_view, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/',views.logout_view,name='logout')
]