"""db/models/resource_read.py

Database Model for tracking resource read status
"""

import sqlalchemy as sa
from sqlalchemy.orm import declarative_base
from .target import Target

Base = declarative_base()


class ResourceRead(Base):
    __tablename__ = 'resource_reads'
    slug = sa.Column(sa.VARCHAR(20), sa.ForeignKey(Target.slug), primary_key=True)
    last_marked_read_at = sa.Column(sa.INTEGER, default=0)
