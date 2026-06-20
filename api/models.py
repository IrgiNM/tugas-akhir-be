from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Permission(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='permissions'
    )
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name
