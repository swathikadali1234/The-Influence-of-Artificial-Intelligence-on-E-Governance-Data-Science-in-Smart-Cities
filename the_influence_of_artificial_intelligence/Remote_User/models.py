from django.db import models

# Create your models here.
from django.db.models import CASCADE


class ClientRegister_Model(models.Model):
    username = models.CharField(max_length=30)
    email = models.EmailField(max_length=30)
    password = models.CharField(max_length=10)
    phoneno = models.CharField(max_length=10)
    country = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    city = models.CharField(max_length=30)
    gender= models.CharField(max_length=30)
    address= models.CharField(max_length=30)


class cyber_attack_detection(models.Model):

    Fid= models.CharField(max_length=3000)
    Timestamp= models.CharField(max_length=3000)
    Source_IP_Address= models.CharField(max_length=3000)
    Destination_IP_Address= models.CharField(max_length=3000)
    Source_Port= models.CharField(max_length=3000)
    Destination_Port= models.CharField(max_length=3000)
    Protocol= models.CharField(max_length=3000)
    Packet_Length= models.CharField(max_length=3000)
    Packet_Type= models.CharField(max_length=3000)
    Traffic_Type= models.CharField(max_length=3000)
    Payload_Data= models.CharField(max_length=3000)
    Malware_Indicators= models.CharField(max_length=3000)
    Anomaly_Scores= models.CharField(max_length=3000)
    Alerts_Warnings= models.CharField(max_length=3000)
    Attack_Signature= models.CharField(max_length=3000)
    Action_Taken= models.CharField(max_length=3000)
    Severity_Level= models.CharField(max_length=3000)
    Device_Information= models.CharField(max_length=3000)
    Network_Segment= models.CharField(max_length=3000)
    Geo_City_location_Data= models.CharField(max_length=3000)
    Proxy_Information= models.CharField(max_length=3000)
    Firewall_Logs= models.CharField(max_length=3000)
    IDS_IPS_Alerts= models.CharField(max_length=3000)
    Log_Source= models.CharField(max_length=3000)
    Prediction= models.CharField(max_length=3000)


class detection_accuracy(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)

class detection_ratio(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)



