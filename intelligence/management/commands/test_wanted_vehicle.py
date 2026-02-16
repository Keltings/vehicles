from django.core.management.base import BaseCommand
from intelligence.models import Vehicle, CustomAlertRule
from django.utils import timezone

class Command(BaseCommand):
    help = 'Test wanted vehicle detection by creating a test entry'

    def handle(self, *args, **kwargs):
        # First, check if there's a wanted vehicle rule
        rule = CustomAlertRule.objects.filter(condition_type='plate_pattern', is_active=True).first()
        
        if not rule or not rule.plate_pattern:
            self.stdout.write(self.style.WARNING('No active wanted vehicle rule found!'))
            self.stdout.write('Create a custom rule with condition type "Plate matches pattern" first.')
            return
        
        # Get first wanted plate
        wanted_plates = [p.strip().upper() for p in rule.plate_pattern.split('\n') if p.strip()]
        
        if not wanted_plates:
            self.stdout.write(self.style.WARNING('No plate numbers in the wanted list!'))
            return
        
        test_plate = wanted_plates[0]
        
        # Create a test vehicle entry
        vehicle = Vehicle.objects.create(
            plate_number=test_plate,
            entry_time=timezone.now(),
            vehicle_type='SUV',
            vehicle_brand='Test',
            plate_color='White',
            site_name='JKIA',
            file_date='Test',
            vehicle_id=f'TEST_{timezone.now().timestamp()}'
        )
        
        self.stdout.write(self.style.SUCCESS(f'✅ Created test entry for wanted vehicle: {test_plate}'))
        self.stdout.write(self.style.SUCCESS('Check the Alerts Center to see if alert was auto-created!'))