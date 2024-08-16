from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from django.urls import reverse_lazy
from django.contrib.auth.models import Group, User
from django.db.models import Q, F
from django.views import View
from django.views.generic import CreateView, ListView, UpdateView, DeleteView
from django.contrib import messages
from app.form import (

    UserForm,
    UserProfileForm,
    UserRegistrationForm,
    UserResetPwdForm,

)

from .models import (
    Profile,
    Account,
    PaymentMethod,

)



def index(request):
    return render(request, "index.html")
    

class UserRegistration(CreateView):
    form_class = UserRegistrationForm
    model = User
    template_name = 'app/user_registration_form.html'

    def get_object(self, queryset=None):
        return self.request.user

    def form_valid(self, form):
        user = form.save()
        password = form.cleaned_data['password']

        user.set_password(password)
        user.save()

        group = Group.objects.get(name='normal_user')
        user.groups.add(group)

        # Create User Profile model
        Profile.objects.create(user=user, birthday=form.clean_birthday(), address=form.clean_address())
        payment = PaymentMethod.objects.create(user=user, method_type='account')
        Account.objects.create(payment=payment)

        return HttpResponseRedirect(reverse_lazy('user_login'))


class UserResetPwd(UpdateView, PermissionRequiredMixin):
    form_class = UserResetPwdForm
    model = User
    template_name = 'app/user_reset_pwd_form.html'
    success_url = 'user_login'
    permission_required = 'app.change_user'

    def get_object(self, queryset=None):
        return self.request.user

    def form_valid(self, form):
        instance = form.save(commit=False)
        instance.user = self.request.user

        password = form.cleaned_data['password']
        instance.user.set_password(password)
        instance.save()

        return HttpResponseRedirect(reverse_lazy('user_login'))





class UserLogin(LoginView):
    def get_success_url(self):
        return reverse_lazy("user_profile")


class UserLogout(LogoutView):
    def get(self, request, *args, **kwargs):
        return HttpResponseRedirect(reverse_lazy('account_login'))

class UserProfile(LoginRequiredMixin, ListView, PermissionRequiredMixin):
    model = User
    template_name = 'app/user_profile_form.html'
    permission_required = 'app.view_profile'


class UserProfileUpdate(LoginRequiredMixin, UpdateView, PermissionRequiredMixin):
    model = User
    form_class = UserForm
    template_name = 'app/user_profile_update.html'
    permission_required = 'app.change_profile'

    def get_object(self, queryset=None):
        return self.request.user

    def get_context_data(self, **kwargs):
        context = super(UserProfileUpdate, self).get_context_data(**kwargs)
        user = self.object
        profile = user.profile
        context['profile_form'] = UserProfileForm(instance=profile)
        return context

    def form_valid(self, form):
        instance = form.save(commit=False)
        instance.user = self.request.user
        instance.save()

        user_profile, create = Profile.objects.update_or_create(user=instance.user)
        user_profile.birthday = self.request.POST['birthday']
        user_profile.address = self.request.POST['address']

        user_profile.save()

        return HttpResponseRedirect(reverse_lazy('profile'))