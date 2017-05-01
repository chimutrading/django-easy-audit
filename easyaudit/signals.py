import logging
from Cookie import SimpleCookie

from django.contrib.auth import signals as auth_signals, get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.models import Session
from django.contrib.contenttypes.models import ContentType
from django.core import serializers
from django.db.models import signals as models_signals
from django.core.signals import request_started
from django.utils import timezone

from .middleware.easyaudit import get_current_request, get_current_user
from .models import CRUDEvent, LoginEvent, RequestEvent
from .settings import UNREGISTERED_CLASSES, WATCH_LOGIN_EVENTS, \
    CRUD_DIFFERENCE_CALLBACKS, WATCH_MODEL_EVENTS, WATCH_REQUEST_EVENTS

logger = logging.getLogger(__name__)


# signals
def post_save(sender, instance, created, raw, using, update_fields, **kwargs):
    """https://docs.djangoproject.com/es/1.10/ref/signals/#post-save"""
    try:
        for unregistered_class in UNREGISTERED_CLASSES:
            if isinstance(instance, unregistered_class):
                return False

        object_json_repr = serializers.serialize("json", [instance])

        # created or updated?
        if created:
            event_type = CRUDEvent.CREATE
        else:
            event_type = CRUDEvent.UPDATE

        # user
        try:
            user = get_current_user()
        except:
            user = None

        if isinstance(user, AnonymousUser):
            user = None

        # callbacks

        # make request available for callbacks
        kwargs['request'] = get_current_request()
        create_crud_event = all(
            callback(instance, object_json_repr, created, raw, using,
                     update_fields, **kwargs)
            for callback in CRUD_DIFFERENCE_CALLBACKS if callable(callback))

        # create crud event only if all callbacks returned True
        if create_crud_event:
            crud_event = CRUDEvent.objects.create(
                event_type=event_type,
                object_repr=str(instance),
                object_json_repr=object_json_repr,
                content_type=ContentType.objects.get_for_model(instance),
                object_id=instance.id,
                user=user,
                datetime=timezone.now(),
                user_pk_as_string=str(user.pk) if user else user
            )

            crud_event.save()
    except Exception:
        logger.exception('easy audit had a post-save exception.')


def post_delete(sender, instance, using, **kwargs):
    """https://docs.djangoproject.com/es/1.10/ref/signals/#post-delete"""
    try:
        for unregistered_class in UNREGISTERED_CLASSES:
            if isinstance(instance, unregistered_class):
                return False

        object_json_repr = serializers.serialize("json", [instance])

        # user
        try:
            user = get_current_user()
        except:
            user = None

        if isinstance(user, AnonymousUser):
            user = None

        # crud event
        crud_event = CRUDEvent.objects.create(
            event_type=CRUDEvent.DELETE,
            object_repr=str(instance),
            object_json_repr=object_json_repr,
            content_type=ContentType.objects.get_for_model(instance),
            object_id=instance.id,
            user=user,
            datetime=timezone.now(),
            user_pk_as_string=str(user.pk) if user else user
        )

        crud_event.save()
    except Exception:
        logger.exception('easy audit had a post-delete exception.')


def user_logged_in(sender, request, user, **kwargs):
    try:
        login_event = LoginEvent(login_type=LoginEvent.LOGIN,
                                 username=getattr(user, user.USERNAME_FIELD),
                                 user=user,
                                 remote_ip=request.META['REMOTE_ADDR'])
        login_event.save()
    except:
        pass


def user_logged_out(sender, request, user, **kwargs):
    try:
        login_event = LoginEvent(login_type=LoginEvent.LOGOUT,
                                 username=getattr(user, user.USERNAME_FIELD),
                                 user=user,
                                 remote_ip=request.META['REMOTE_ADDR'])
        login_event.save()
    except:
        pass


def user_login_failed(sender, credentials, **kwargs):
    try:
        user_model = get_user_model()
        login_event = LoginEvent(login_type=LoginEvent.FAILED,
                                 username=credentials[user_model.USERNAME_FIELD])
        login_event.save()
    except:
        pass


def request_started_handler(sender, environ, **kwargs):
    cookie = SimpleCookie()
    cookie.load(environ['HTTP_COOKIE'])
    user = None
    if 'sessionid' in cookie:
        session_id = cookie['sessionid'].value
        try:
            session = Session.objects.get(session_key=session_id)
        except Session.DoesNotExist:
            session = None
        if session:
            user_id = session.get_decoded()['_auth_user_id']
            try:
                user = get_user_model().objects.get(id=user_id)
            except:
                user = None

    request_event = RequestEvent.objects.create(
        uri=environ['PATH_INFO'],
        type=environ['REQUEST_METHOD'],
        query_string=environ['QUERY_STRING'],
        user=user,
        remote_ip=environ['REMOTE_ADDR'],
        datetime=timezone.now()
    )

    request_event.save()


if WATCH_MODEL_EVENTS:
    models_signals.post_save.connect(post_save,
                                     dispatch_uid='easy_audit_signals_post_save')
    models_signals.post_delete.connect(post_delete,
                                       dispatch_uid='easy_audit_signals_post_delete')

if WATCH_REQUEST_EVENTS:
    request_started.connect(request_started_handler,
                        dispatch_uid='easy_audit_signals_request_started')

if WATCH_LOGIN_EVENTS:
    auth_signals.user_logged_in.connect(user_logged_in,
                                        dispatch_uid='easy_audit_signals_logged_in')
    auth_signals.user_logged_out.connect(user_logged_out,
                                         dispatch_uid='easy_audit_signals_logged_out')
    auth_signals.user_login_failed.connect(user_login_failed,
                                           dispatch_uid='easy_audit_signals_login_failed')
