from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login ,logout
from django.contrib.auth.forms import AuthenticationForm
from .forms import SignupForm, LoginForm
from django.contrib.auth.decorators import login_required
from ai_detector.decorators import trigger_network_capture

@trigger_network_capture(packet_count=300, output_file='/app/data/captured_traffic_features.csv')
@login_required
def homepage(request):
    return render(request, 'homepage.html', {'user': request.user})


@trigger_network_capture(packet_count=300, output_file='/app/data/captured_traffic_features.csv')
def signup_view(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            return redirect('login')
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})

@trigger_network_capture(packet_count=300, output_file='/app/data/captured_traffic_features.csv')
def login_view(request):
    if request.method == 'POST':
        form = LoginForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('homepage')  # Redirect to a page after login
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})


@trigger_network_capture(packet_count=300, output_file='/app/data/captured_traffic_features.csv')
def logout_view(request):
    logout(request)
    return redirect('login')