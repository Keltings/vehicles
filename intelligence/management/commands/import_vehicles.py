from django.core.management.base import BaseCommand
from intelligence.models import Vehicle
import csv
from datetime import datetime
from django.utils import timezone

class Command(BaseCommand):
    help = 'Import vehicles from CSV'
    
    def handle(self, *args, **kwargs):
        self.stdout.write('📊 Starting import...')
        
        with open('vehicle_data.csv', 'r') as file:
            reader = csv.DictReader(file)
            count = 0
            
            for row in reader:
                try:
                    entry_time = datetime.strptime(row['Entry Time'], '%Y-%m-%d %H:%M:%S')
                    entry_time = timezone.make_aware(entry_time)
                    
                    exit_time = None
                    if row['Exit Time']:
                        exit_time = datetime.strptime(row['Exit Time'], '%Y-%m-%d %H:%M:%S')
                        exit_time = timezone.make_aware(exit_time)
                    
                    Vehicle.objects.create(
                        plate_number=row['Plate Number'],
                        entry_time=entry_time,
                        exit_time=exit_time,
                        vehicle_type=row['Vehicle Type'],
                        plate_color=row['Plate Color'],
                        vehicle_brand=row['Vehicle Brand'],
                        amount_paid=float(row['Amount Paid']) if row['Amount Paid'] else 0,
                        payment_method=row['Payment Method'],
                        site_name=row['Site Name'],
                        file_date=row['File Date'],
                        vehicle_id=row['Vehicle Id']
                    )
                    count += 1
                    if count % 1000 == 0:
                        self.stdout.write(f'Imported {count}...')
                except Exception as e:
                    self.stdout.write(f'Error: {e}')
            
            self.stdout.write(f'✅ Done! Imported {count} vehicles')