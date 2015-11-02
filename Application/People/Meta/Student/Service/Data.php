<?php
namespace SPHERE\Application\People\Meta\Student\Service;

use SPHERE\Application\People\Meta\Student\Service\Entity\TblStudent;
use SPHERE\Application\People\Meta\Student\Service\Entity\TblStudentAgreementCategory;
use SPHERE\Application\People\Meta\Student\Service\Entity\TblStudentAgreementType;
use SPHERE\Application\People\Meta\Student\Service\Entity\TblStudentMedicalRecord;
use SPHERE\Application\People\Meta\Student\Service\Entity\TblStudentTransfer;
use SPHERE\Application\People\Meta\Student\Service\Entity\TblStudentTransferArrive;
use SPHERE\Application\People\Meta\Student\Service\Entity\TblStudentTransferEnrollment;
use SPHERE\Application\People\Meta\Student\Service\Entity\TblStudentTransferLeave;
use SPHERE\Application\People\Meta\Student\Service\Entity\TblStudentTransferProcess;
use SPHERE\Application\People\Person\Service\Entity\TblPerson;
use SPHERE\Application\Platform\System\Protocol\Protocol;
use SPHERE\System\Database\Binding\AbstractData;

/**
 * Class Data
 *
 * @package SPHERE\Application\People\Meta\Student\Service
 */
class Data extends AbstractData
{

    public function setupDatabaseContent()
    {

        $this->createStudentAgreementCategory(
            'Foto des Schülers',
            'Sowohl Einzelaufnahmen als auch in Gruppen (z.B. zufällig)'
        );
        $this->createStudentAgreementType('in Schulschriften');
        $this->createStudentAgreementType('in Veröffentlichungen');
        $this->createStudentAgreementType('auf Internetpräsenz');
        $this->createStudentAgreementType('auf Facebookseite');
        $this->createStudentAgreementType('für Druckpresse');
        $this->createStudentAgreementType('durch Ton/Video/Film');
        $this->createStudentAgreementType('für Werbung in eigener Sache');
    }

    /**
     * @param string $Name
     * @param string $Description
     *
     * @return TblStudentAgreementCategory
     */
    public function createStudentAgreementCategory($Name, $Description = '')
    {

        $Manager = $this->getConnection()->getEntityManager();
        $Entity = $Manager->getEntity('TblStudentAgreementCategory')->findOneBy(array(
            TblStudentAgreementCategory::ATTR_NAME => $Name
        ));
        if (null === $Entity) {
            $Entity = new TblStudentAgreementCategory();
            $Entity->setName($Name);
            $Entity->setDescription($Description);
            $Manager->saveEntity($Entity);
            Protocol::useService()->createInsertEntry($this->getConnection()->getDatabase(), $Entity);
        }
        return $Entity;
    }

    /**
     * @param string $Name
     * @param string $Description
     *
     * @return TblStudentAgreementType
     */
    public function createStudentAgreementType($Name, $Description = '')
    {

        $Manager = $this->getConnection()->getEntityManager();
        $Entity = $Manager->getEntity('TblStudentAgreementType')->findOneBy(array(
            TblStudentAgreementType::ATTR_NAME => $Name
        ));
        if (null === $Entity) {
            $Entity = new TblStudentAgreementType();
            $Entity->setName($Name);
            $Entity->setDescription($Description);
            $Manager->saveEntity($Entity);
            Protocol::useService()->createInsertEntry($this->getConnection()->getDatabase(), $Entity);
        }
        return $Entity;
    }

    /**
     * @param TblPerson               $tblPerson
     * @param TblStudentMedicalRecord $tblStudentMedicalRecord
     *
     * @return TblStudent
     */
    public function createStudent(
        TblPerson $tblPerson,
        TblStudentMedicalRecord $tblStudentMedicalRecord
    ) {

        $Manager = $this->getConnection()->getEntityManager();

        $Entity = new TblStudent();
        $Entity->setServiceTblPerson($tblPerson);
        $Entity->setTblStudentMedicalRecord($tblStudentMedicalRecord);
        $Manager->saveEntity($Entity);
        Protocol::useService()->createInsertEntry($this->getConnection()->getDatabase(), $Entity);

        return $Entity;
    }

    /**
     * @param int $Id
     *
     * @return bool|TblStudent
     */
    public function getStudentById($Id)
    {

        return $this->getCachedEntityById(__METHOD__, $this->getConnection()->getEntityManager(), 'TblStudent', $Id);
    }

    /**
     * @param TblPerson $tblPerson
     *
     * @return bool|TblStudent
     */
    public function getStudentByPerson(TblPerson $tblPerson)
    {

        return $this->getCachedEntityBy(__METHOD__, $this->getConnection()->getEntityManager(), 'TblStudent', array(
            TblStudent::SERVICE_TBL_PERSON => $tblPerson->getId()
        ));
    }

    /**
     * @param string         $Disease
     * @param string         $Medication
     * @param null|TblPerson $tblPersonAttendingDoctor
     * @param int            $InsuranceState
     * @param string         $Insurance
     *
     * @return TblStudentMedicalRecord
     */
    public function createStudentMedicalRecord(
        $Disease,
        $Medication,
        TblPerson $tblPersonAttendingDoctor,
        $InsuranceState,
        $Insurance
    ) {

        $Manager = $this->getConnection()->getEntityManager();

        $Entity = new TblStudentMedicalRecord();
        $Entity->setDisease($Disease);
        $Entity->setMedication($Medication);
        $Entity->setServiceTblPersonAttendingDoctor($tblPersonAttendingDoctor);
        $Entity->setInsuranceState($InsuranceState);
        $Entity->setInsurance($Insurance);
        $Manager->saveEntity($Entity);
        Protocol::useService()->createInsertEntry($this->getConnection()->getDatabase(), $Entity);

        return $Entity;
    }

    /**
     * @param TblStudentMedicalRecord $tblStudentMedicalRecord
     * @param string                  $Disease
     * @param string                  $Medication
     * @param null|TblPerson          $tblPersonAttendingDoctor
     * @param int                     $InsuranceState
     * @param string                  $Insurance
     *
     * @return TblStudentMedicalRecord
     */
    public function updateStudentMedicalRecord(
        TblStudentMedicalRecord $tblStudentMedicalRecord,
        $Disease,
        $Medication,
        TblPerson $tblPersonAttendingDoctor,
        $InsuranceState,
        $Insurance
    ) {

        $Manager = $this->getConnection()->getEntityManager();
        /** @var null|TblStudentMedicalRecord $Entity */
        $Entity = $Manager->getEntityById('TblStudentMedicalRecord', $tblStudentMedicalRecord->getId());
        if (null !== $Entity) {
            $Protocol = clone $Entity;
            $Entity->setDisease($Disease);
            $Entity->setMedication($Medication);
            $Entity->setServiceTblPersonAttendingDoctor($tblPersonAttendingDoctor);
            $Entity->setInsuranceState($InsuranceState);
            $Entity->setInsurance($Insurance);
            $Manager->saveEntity($Entity);
            Protocol::useService()->createUpdateEntry($this->getConnection()->getDatabase(), $Protocol, $Entity);
            return true;
        }
        return false;
    }

    /**
     * @param int $Id
     *
     * @return bool|TblStudentMedicalRecord
     */
    public function getStudentMedicalRecordById($Id)
    {

        return $this->getCachedEntityById(__METHOD__, $this->getConnection()->getEntityManager(),
            'TblStudentMedicalRecord',
            $Id);
    }

    /**
     * @param int $Id
     *
     * @return bool|TblStudentTransfer
     */
    public function getStudentTransferById($Id)
    {

        return $this->getCachedEntityById(__METHOD__, $this->getConnection()->getEntityManager(), 'TblStudentTransfer',
            $Id);
    }

    /**
     * @param int $Id
     *
     * @return bool|TblStudentTransferArrive
     */
    public function getStudentTransferArriveById($Id)
    {

        return $this->getCachedEntityById(__METHOD__, $this->getConnection()->getEntityManager(),
            'TblStudentTransferArrive',
            $Id);
    }

    /**
     * @param int $Id
     *
     * @return bool|TblStudentTransferEnrollment
     */
    public function getStudentTransferEnrollmentById($Id)
    {

        return $this->getCachedEntityById(__METHOD__, $this->getConnection()->getEntityManager(),
            'TblStudentTransferEnrollment',
            $Id);
    }

    /**
     * @param int $Id
     *
     * @return bool|TblStudentTransferLeave
     */
    public function getStudentTransferLeaveById($Id)
    {

        return $this->getCachedEntityById(__METHOD__, $this->getConnection()->getEntityManager(),
            'TblStudentTransferLeave',
            $Id);
    }

    /**
     * @param int $Id
     *
     * @return bool|TblStudentTransferProcess
     */
    public function getStudentTransferProcessById($Id)
    {

        return $this->getCachedEntityById(__METHOD__, $this->getConnection()->getEntityManager(),
            'TblStudentTransferProcess',
            $Id);
    }
}
