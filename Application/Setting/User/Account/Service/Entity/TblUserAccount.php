<?php
namespace SPHERE\Application\Setting\User\Account\Service\Entity;

use Doctrine\ORM\Mapping\Cache;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\Table;
use SPHERE\Application\People\Person\Person;
use SPHERE\Application\People\Person\Service\Entity\TblPerson;
use SPHERE\Application\Platform\Gatekeeper\Authorization\Account\Service\Entity\TblAccount;
use SPHERE\Application\Setting\Authorization\Account\Account;
use SPHERE\System\Database\Fitting\Element;

/**
 * @Entity
 * @Table(name="tblUserAccount")
 * @Cache(usage="READ_ONLY")
 */
class TblUserAccount extends Element
{

    const VALUE_TYPE_STUDENT = 'STUDENT';
    const VALUE_TYPE_CUSTODY = 'CUSTODY';

    const ATTR_SERVICE_TBL_ACCOUNT = 'serviceTblAccount';
    const ATTR_SERVICE_TBL_PERSON = 'serviceTblPerson';
//    const ATTR_SERVICE_TBL_TO_PERSON_ADDRESS = 'serviceTblToPersonAddress';
    const ATTR_TYPE = 'type';
//    const ATTR_SERVICE_TBL_TO_PERSON_MAIL = 'serviceTblToPersonMail';
    const ATTR_USER_PASSWORD = 'UserPassword';
    const ATTR_ACCOUNT_PASSWORD = 'AccountPassword';
//    const ATTR_IS_SEND = 'IsSend';
    const ATTR_IS_EXPORT = 'IsExport';
    const ATTR_GROUP_BY_TIME = 'groupByTime';

    /**
     * @Column(type="bigint")
     */
    protected $serviceTblAccount;
    /**
     * @Column(type="bigint")
     */
    protected $serviceTblPerson;
//    /**
//     * @Column(type="bigint")
//     */
//    protected $serviceTblToPersonAddress;
//    /**
//     * @Column(type="bigint")
//     */
//    protected $serviceTblToPersonMail;
    /**
     * @Column(type="string")
     */
    protected $type;
    /**
     * @Column(type="string")
     */
    protected $UserPassword;
    /**
     * @Column(type="string")
     */
    protected $AccountPassword;
//    /**
//     * @Column(type="boolean")
//     */
//    protected $IsSend;
    /**
     * @Column(type="boolean")
     */
    protected $IsExport;
    /**
     * @Column(type="datetime")
     */
    protected $groupByTime;

    /**
     * @return false|TblPerson
     */
    public function getServiceTblPerson()
    {

        $tblPerson = ($this->serviceTblPerson != null
            ? Person::useService()->getPersonById($this->serviceTblPerson)
            : false);
        if ($tblPerson) {
            return $tblPerson;
        }
        return false;
    }

    /**
     * @param null|TblPerson $tblPerson
     */
    public function setServiceTblPerson(TblPerson $tblPerson = null)
    {

        $this->serviceTblPerson = ( null === $tblPerson ? null : $tblPerson->getId() );
    }

    /**
     * @return false|TblAccount
     */
    public function getServiceTblAccount()
    {

        $tblAccount = ($this->serviceTblAccount != null
            ? Account::useService()->getAccountById($this->serviceTblAccount)
            : false);
        if ($tblAccount) {
            return $tblAccount;
        }
        return false;
    }

    /**
     * @param TblAccount|null $tblAccount
     */
    public function setServiceTblAccount(TblAccount $tblAccount = null)
    {

        $this->serviceTblAccount = (null === $tblAccount ? null : $tblAccount->getId());
    }

//    /**
//     * @return false|TblToPersonAddress
//     */
//    public function getServiceTblToPersonAddress()
//    {
//
//        $tblToPersonAddress = ( $this->serviceTblToPersonAddress != null
//            ? Address::useService()->getAddressToPersonById($this->serviceTblToPersonAddress)
//            : false );
//        if ($tblToPersonAddress) {
//            return $tblToPersonAddress;
//        }
//        return false;
//    }
//
//    /**
//     * @param null|TblToPersonAddress $tblToPersonAddress
//     */
//    public function setServiceTblToPersonAddress(TblToPersonAddress $tblToPersonAddress = null)
//    {
//
//        $this->serviceTblToPersonAddress = ( null === $tblToPersonAddress ? null : $tblToPersonAddress->getId() );
//    }

//    /**
//     * @return false|TblToPersonMail
//     */
//    public function getServiceTblToPersonMail()
//    {
//
//        $tblToPersonMail = ( $this->serviceTblToPersonMail != null
//            ? Mail::useService()->getMailToPersonById($this->serviceTblToPersonMail)
//            : false );
//        if ($tblToPersonMail) {
//            return $tblToPersonMail;
//        }
//        return false;
//    }
//
//    /**
//     * @param null|TblToPersonMail $tblToPersonMail
//     */
//    public function setServiceTblToPersonMail(TblToPersonMail $tblToPersonMail = null)
//    {
//
//        $this->serviceTblToPersonMail = ( null === $tblToPersonMail ? null : $tblToPersonMail->getId() );
//    }

    /**
     * @return mixed
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * @param mixed $type
     */
    public function setType($type)
    {
        $this->type = $type;
    }

    /**
     * @return string
     */
    public function getUserPassword()
    {
        return $this->UserPassword;
    }

    /**
     * @param string $UserPassword
     */
    public function setUserPassword($UserPassword = '')
    {
        $this->UserPassword = $UserPassword;
    }

    /**
     * @return mixed
     */
    public function getAccountPassword()
    {
        return $this->AccountPassword;
    }

    /**
     * @param mixed $AccountPassword
     */
    public function setAccountPassword($AccountPassword)
    {
        $this->AccountPassword = $AccountPassword;
    }

//    /**
//     * @return string
//     */
//    public function getIsSend()
//    {
//        return $this->IsSend;
//    }
//
//    /**
//     * @param string $IsSend
//     */
//    public function setIsSend($IsSend = '')
//    {
//        $this->IsSend = $IsSend;
//    }

    /**
     * @return string
     */
    public function getIsExport()
    {
        return $this->IsExport;
    }

    /**
     * @param string $IsExport
     */
    public function setIsExport($IsExport = '')
    {
        $this->IsExport = $IsExport;
    }

    /**
     * @return bool|string
     */
    public function getGroupByTime()
    {

        /** @var \DateTime $groupByTime */
        $groupByTime = $this->groupByTime;
        if ($groupByTime instanceof \DateTime) {
            return $groupByTime->format('d.m.Y H:i:s');
//            return $groupByTime;
        }
        return false;
    }

    /**
     * @param \DateTime $DateTime
     */
    public function setGroupByTime($DateTime)
    {

        $this->groupByTime = $DateTime;
    }
}
