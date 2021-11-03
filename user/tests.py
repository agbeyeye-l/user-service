from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from user.models import UserProfile, DefaultPermission
from faker import Faker

faker = Faker()
class Permissions():
    DEFAULT=['c','r','u','d']


# create a user in the db
def add_default_permission(role):
    permission = DefaultPermission.objects.create(
                                role = role,
                                post = Permissions.DEFAULT,
                                story = Permissions.DEFAULT,
                                gallery = Permissions.DEFAULT,
                                shelf = Permissions.DEFAULT,
                                book = Permissions.DEFAULT,
                                announcement = Permissions.DEFAULT,
                                event = Permissions.DEFAULT,
                                suggestion = Permissions.DEFAULT
                                )
    permission.save()

def generate_user(role):
    return {
            'email':faker.email(),
            'password':faker.password(),
            'first_name':faker.first_name(),
            'last_name': faker.last_name(),
            'role': role,
            'bio':faker.text(),
            'nationality':faker.word(),
            'phone_number':faker.phone_number(),
            'avatar':faker.url(),
            'label':faker.word()
            }


# add a user to db
# def add_post_to_db():
#     a_post = Post.objects.create(createdBy= UserProfile.objects.get(pk=1),
#                                 title= faker.word(),
#                                 body= faker.text(),
#                                 picture= faker.url()
#                                 )
#     a_post.save()


class UserTest(APITestCase):
    """
    This test class contains all CRUD operations on user objects
    """

    def test_create_user(self):
        """
        Ensure we can create a new post object.
        """
        # create default permission for a role
        add_default_permission('STUDENT')
        # get url for creating a post
        url = reverse('users')
        data = generate_user('STUDENT')
        # create new post
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_get_post(self):
        """
        Ensure we can get post instances from db.
        """
        # create default permission for a role
        add_default_permission('STAFF')
        # add users of type staff
        staff = generate_user('STAFF')
        # get url for creating a post
        url = reverse('users')
        staff_creation_response = self.client.post(url, data=staff)
        #  get users
        response = self.client.get(url)
        self.assertEqual(staff_creation_response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # def test_update_user(self):
    #     # create default permission for a role
    #     add_default_permission('STUDENT')
    #     # get url for creating a post
    #     url = reverse('users')
    #     data = generate_user('STUDENT')
    #     # create new post
    #     response = self.client.post(url, data=data)
    #     update_url = reverse('user-detail',args=[int(response.data['id'])])
    #     update_response = self.client.patch(update_url,{'id':response.data['id'], 'first_name':faker.first_name()})
    #     self.assertEqual(response.status_code, status.HTTP_201_CREATED)
    #     self.assertEqual(update_response.status_code, status.HTTP_200_OK)


