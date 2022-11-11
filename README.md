# Users
This microservice allows register user and login (create jwt)
To run:
1. Open solution in Visual Studio 2022 Community Edition
2. Add users Secrets file
Below is the User Secrets file format
{
   "CustomSettings:EmailServerSettings:Username": "casectrl123@outlook.com",
   "CustomSettings:EmailServerSettings:Password": "Aszx9080",
   "ConnectionStrings:AuthenticationContextConnection": - connection string to any empty SQL Server Database to AuthenticationContextConnection.
   "CustomSettings:Jwt:Key": "AJjowquxjJOIH*&QS870jqw8w8h"
}
3. In package management console in Visual Studio run Update-Database to create required tables
4. Run in Debug/Release mode