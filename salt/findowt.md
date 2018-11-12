이 Salt Orchestraton 코드는 ELB, Confidant ASG, auth 및 at-rest 암호화를위한 인덱스 및 KMS 키가있는 DynamoDB 테이블을 사용하여 Confidant 인프라를 시작하는 데 사용할 수 있습니다.  
이 오케스트레이션 코드는 AWS에서 인프라를 시작하며 요금이 부과됩니다. AWS 리소스의 이름 지정을 위해 미리 정의 된 형식을 사용합니다.  
* service_name-service_instance-region  
 service_name, service_instance 및 region은 환경 변수를 통해 사용자가 지정합니다.  
#솔트 스테이트 시스템의 핵심은 SLS 또는 SaLt State 파일입니다. 
#SLS는 시스템이 있어야하며 간단한 형식으로 이 데이터를 포함하도록 설정되는 상태를 나타냅니다. 
#이를 종종 구성 관리라고합니다.  
