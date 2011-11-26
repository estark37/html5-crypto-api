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


from django.shortcuts import render_to_response
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from safemsg.models import UserInfo, Msg
from django.http import HttpResponse, HttpResponseRedirect
from urllib import quote_plus

def index(request):
  user = None
  attempted_login = False
  profile = None
  msgs = None
  if request.user and request.user.is_authenticated():
    user = request.user
    profile = UserInfo.objects.get(user=user)
    msgs = Msg.objects.filter(recipient=user)
  elif request.POST.get("register"):
    user = User.objects.create_user(request.POST.get("username"), request.POST.get("username"), request.POST.get("password"))
    user.save()

    profile = UserInfo(user=user)
    profile.save()

    msgs = Msg.objects.filter(recipient=user)

    user = authenticate(username=request.POST.get("username"), password=request.POST.get("password"))
    login(request, user)
  elif request.POST.get("login"):
    user = authenticate(username=request.POST.get("username"), password=request.POST.get("password"))
    attempted_login = True
    if user is not None:
      login(request, user)
      profile = UserInfo.objects.get(user=user)
      msgs = Msg.objects.filter(recipient=user)
  return render_to_response('safemsg/index.html', {"user": user, "attempted_login": attempted_login, "profile": profile, "msgs": msgs})

def logout_view(request):
  logout(request)
  return HttpResponseRedirect('/safemsg')

def keypair(request):
  if (not (request.user and request.user.is_authenticated())):
    return HttpResponse(status=403)

  if (request.method == "POST"):
    profile = UserInfo.objects.get(user=request.user)
    profile.keypair = request.POST.get("keypair")
    profile.publickey = request.POST.get("publickey")
    profile.save()
    return HttpResponse(status=200)

  return HttpResponse(status=500)

def publickey(request):
  if (not (request.user and request.user.is_authenticated())):
    return HttpResponse(status=403)

  if (request.method == "GET" and request.GET.get("recipient")):
    recpt = User.objects.get(username = request.GET.get("recipient"))
    profile = UserInfo.objects.get(user = recpt)
    return HttpResponse(status=200, content=profile.publickey)

  return HttpResponse(status=500)

def send(request):
  if (not (request.user and request.user.is_authenticated() and request.method == "POST")):
    return HttpResponse(status=403)

  recipient = User.objects.get(username=request.POST.get("recipient"))
  msg = Msg(recipient=recipient, sender=request.user, subject=request.POST.get("subject"), msg=quote_plus(request.POST.get("msg")))
  msg.save()
  return HttpResponse(status=200)

def message(request):
  if (not (request.user and request.user.is_authenticated() and request.method == "GET")):
    return HttpResponse(status=403)

  id = request.GET.get("id")
  msg = Msg.objects.get(id=id)
  if (not msg.recipient == request.user):
    return HttpResponse(status=403)

  return HttpResponse(msg.msg)
