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


from django.db import models
from django.contrib.auth.models import User

class UserInfo(models.Model):
  user = models.OneToOneField(User, related_name='safemsg_user')
  keypair = models.CharField(max_length=5000)
  publickey = models.CharField(max_length=5000)

class Msg(models.Model):
  sender = models.ForeignKey(User, related_name='safemsg_sender')
  recipient = models.ForeignKey(User, related_name='safemsg_recipient')
  subject = models.CharField(max_length=200)
  msg = models.CharField(max_length=5000)
