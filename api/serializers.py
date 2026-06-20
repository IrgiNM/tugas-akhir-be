from django.contrib.auth.models import User
from rest_framework import serializers
from .models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','username', 'password', 'email', 'is_staff']
        extra_kwargs = {
            'password': {'write_only': True},
            'username': {'required': True},
            'email': {'required': True} # 'write_only' artinya password tidak akan
                                             # dikirim balik di respon (biar aman)
        }

    def create(self, validated_data):
        # Kita pakai create_user agar password-nya di-hash (dienkripsi)
        # BUKAN disimpan sebagai teks biasa. Ini WAJIB!
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user
    
    def update(self, instance, validated_data):
        # Update username / email / is_staff
        for attr, value in validated_data.items():
            if attr == 'password':
                # pakai set_password agar di-hash
                instance.set_password(value)
            else:
                setattr(instance, attr, value)

        instance.save()
        return instance

    def validate(self, data):
        emailData = data.get('email')
        if emailData:
            # Pastikan email unik, tetapi abaikan dirinya sendiri saat update
            user_id = self.instance.id if self.instance else None
            if User.objects.filter(email=emailData).exclude(id=user_id).exists():
                raise serializers.ValidationError("email udah ada")
        return data
    
class PermissionSerializer(serializers.ModelSerializer):
    user_detail = UserSerializer(source='user', read_only=True)

    class Meta:
        model = Permission
        fields = [
            'id',
            'user',
            'user_detail',
            'name'
        ]
    