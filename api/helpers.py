from django.contrib.auth.models import User

def UserCheckRole(user):
    user_obj = User.objects.get(username=user.username)
    if user_obj.is_staff:
        return True
    return False
