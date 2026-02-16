from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Vehicle
from .views import check_custom_rules

@receiver(post_save, sender=Vehicle)
def auto_check_rules(sender, instance, created, **kwargs):
    """
    Automatically check custom alert rules when a vehicle is created or updated
    This enables real-time detection of wanted vehicles and other conditions
    """
    if created:  # Only check on new entries
        try:
            check_custom_rules(instance)
        except Exception as e:
            print(f"Error checking custom rules for {instance.plate_number}: {e}")