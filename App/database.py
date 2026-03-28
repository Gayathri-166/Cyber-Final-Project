from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

engine = create_engine("sqlite:///vuln.db")
Session = sessionmaker(bind=engine)
Base = declarative_base()

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    ip = Column(String)
    port = Column(Integer)
    state = Column(String)
    service = Column(String)
    severity = Column(String)
    risk_score = Column(Integer)

Base.metadata.create_all(engine)