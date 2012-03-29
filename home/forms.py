from django import forms

class CreateUserForm(forms.Form):
	username = forms.CharField(max_length=30)
	password = forms.CharField(min_length=5)
	confirm_password = forms.CharField()
	email = forms.EmailField()
	
	def clean(self):
		if self.cleaned_data.has_key('confirm_password') and self.cleaned_data.has_key('password'):
			if self.cleaned_data['confirm_password']!=self.cleaned_data['password']:
				raise forms.ValidationError("Passwords don't match")
		return self.cleaned_data