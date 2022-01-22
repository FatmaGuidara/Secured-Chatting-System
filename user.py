import uuid

class User:
    def __init__(self, firstName, lastName, email, password):
        self.id =str(uuid.uuid4())
        self.firstName = firstName
        self.lastName = lastName
        self.email = email
        self.password = password
