from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class MyData(Base):
    __tablename__ = 'my_data'
    id = Column(Integer, primary_key=True)
    data_value = Column(String)

class Database:
    def __init__(self, db_url):
        self.engine = create_engine(db_url)
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def store(self, data):
        try:
            # Create a new record
            new_record = MyData(data_value=data)
            self.session.add(new_record)
            self.session.commit()
            print("Data stored successfully!")
        except Exception as e:
            self.session.rollback()
            print(f"Error storing data: {e}")

if __name__ == "__main__":
    db_url = "sqlite:///my_database.db"  # Replace with your database URL
    db = Database(db_url)
    data_to_store = "Sample data"
    db.store(data_to_store)
