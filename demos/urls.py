from django.conf.urls.defaults import *

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    (r'^bank/$', 'bank.views.index'),
    (r'^bank/logout$', 'bank.views.logout_view'),
    (r'^bank/keypair$', 'bank.views.keypair'),
    (r'^bank/balance$', 'bank.views.balance'),
    (r'^bank/transfer$', 'bank.views.transfer'),
    (r'^safemsg/$', 'safemsg.views.index'),
    (r'^safemsg/logout$', 'safemsg.views.logout_view'),
    (r'^safemsg/keypair$', 'safemsg.views.keypair'),
    (r'^safemsg/publickey$', 'safemsg.views.publickey'),
    (r'^safemsg/send$', 'safemsg.views.send'),
    (r'^safemsg/message$', 'safemsg.views.message'),
    (r'^site_media/(?P<path>.*)$', 'django.views.static.serve',
        {'document_root': '/PATH/TO/html5-crypto-api/src/'})
    # Example:
    # (r'^demos/', include('demos.foo.urls')),

    # Uncomment the admin/doc line below and add 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # (r'^admin/', include(admin.site.urls)),
)
