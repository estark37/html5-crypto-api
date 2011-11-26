#Copyright 2011 Google Inc. All Rights Reserved.
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at

#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.


from os import system
from django.shortcuts import render_to_response
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from bank.models import UserInfo
from django.http import HttpResponse, HttpResponseRedirect
from urllib import quote

def index(request):
  user = None
  attempted_login = False
  profile = None
  if request.user and request.user.is_authenticated():
    user = request.user
    profile = UserInfo.objects.get(user=user)
  elif request.POST.get("register"):
    user = User.objects.create_user(request.POST.get("username"), request.POST.get("username"), request.POST.get("password"))
    user.save()

    profile = UserInfo(user=user, balance=20)
    profile.save()

    user = authenticate(username=request.POST.get("username"), password=request.POST.get("password"))
    login(request, user)
  elif request.POST.get("login"):
    user = authenticate(username=request.POST.get("username"), password=request.POST.get("password"))
    attempted_login = True
    if user is not None:
      login(request, user)
      profile = UserInfo.objects.get(user=user)
  return render_to_response('bank/index.html', {"user": user, "attempted_login": attempted_login, "profile": profile})

def logout_view(request):
  logout(request)
  return HttpResponseRedirect('/bank')

def keypair(request):
  if (not request.method == 'POST' or not (request.user and request.user.is_authenticated())):
    return HttpResponse(status=403)

  profile = UserInfo.objects.get(user=request.user)
  profile.keypair = request.POST.get("keypair")
  profile.save()
  return HttpResponse(status=200)

def transfer(request):
  if (not request.method == 'POST' or not (request.user and request.user.is_authenticated())):
    return HttpResponse(status=403)

  cmd = "rhino verify_sig.js " + request.POST.get("pk") + " " + quote(request.POST.get("stmt")) + " " + request.POST.get("sig");
  ret = system(cmd)

  if (ret):
    # We couldn't verify the transaction
    return HttpResponse(status=500)

  from_profile = UserInfo.objects.get(user=request.user)
  to_profile = UserInfo.objects.get(user=User.objects.get(username=request.POST.get("to")))

  amount = int(request.POST.get("amount"))
  from_profile.balance = from_profile.balance - amount
  to_profile.balance = to_profile.balance + amount

  from_profile.save()
  to_profile.save()
  return HttpResponse(status=200)

def balance(request):
  if (not (request.user and request.user.is_authenticated())):
    return HttpResponse(status=403)

  profile = UserInfo.objects.get(user=request.user)
  return HttpResponse(profile.balance)
