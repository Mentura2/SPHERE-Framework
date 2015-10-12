<?php
namespace SPHERE\Application\People\Relationship\Service;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\DBAL\Schema\Table;
use SPHERE\System\Database\Binding\AbstractSetup;

/**
 * Class Setup
 *
 * @package SPHERE\Application\People\Relationship\Service
 */
class Setup extends AbstractSetup
{

    /**
     * @param bool $Simulate
     *
     * @return string
     */
    public function setupDatabaseSchema($Simulate = true)
    {

        /**
         * Table
         */
        $Schema = clone $this->getConnection()->getSchema();
        $tblType = $this->setTableType($Schema);
        $this->setTableToPerson($Schema, $tblType);
        $this->setTableToCompany($Schema, $tblType);
        /**
         * Migration & Protocol
         */
        $this->getConnection()->addProtocol(__CLASS__);
        $this->getConnection()->setMigration($Schema, $Simulate);
        return $this->getConnection()->getProtocol($Simulate);
    }

    /**
     * @param Schema $Schema
     *
     * @return Table
     */
    private function setTableType(Schema &$Schema)
    {

        $Table = $this->getConnection()->createTable($Schema, 'tblType');
        if (!$this->getConnection()->hasColumn('tblType', 'Name')) {
            $Table->addColumn('Name', 'string');
        }
        if (!$this->getConnection()->hasColumn('tblType', 'Description')) {
            $Table->addColumn('Description', 'string');
        }
        if (!$this->getConnection()->hasColumn('tblType', 'IsLocked')) {
            $Table->addColumn('IsLocked', 'boolean');
        }
        return $Table;
    }

    /**
     * @param Schema $Schema
     * @param Table  $tblType
     *
     * @return Table
     */
    private function setTableToPerson(Schema &$Schema, Table $tblType)
    {

        $Table = $this->getConnection()->createTable($Schema, 'tblToPerson');
        if (!$this->getConnection()->hasColumn('tblToPerson', 'Remark')) {
            $Table->addColumn('Remark', 'text');
        }
        if (!$this->getConnection()->hasColumn('tblToPerson', 'serviceTblPersonFrom')) {
            $Table->addColumn('serviceTblPersonFrom', 'bigint', array('notnull' => false));
        }
        if (!$this->getConnection()->hasColumn('tblToPerson', 'serviceTblPersonTo')) {
            $Table->addColumn('serviceTblPersonTo', 'bigint', array('notnull' => false));
        }
        $this->getConnection()->addForeignKey($Table, $tblType);
        return $Table;
    }

    /**
     * @param Schema $Schema
     * @param Table  $tblType
     *
     * @return Table
     */
    private function setTableToCompany(Schema &$Schema, Table $tblType)
    {

        $Table = $this->getConnection()->createTable($Schema, 'tblToCompany');
        if (!$this->getConnection()->hasColumn('tblToCompany', 'Remark')) {
            $Table->addColumn('Remark', 'text');
        }
        if (!$this->getConnection()->hasColumn('tblToCompany', 'serviceTblCompany')) {
            $Table->addColumn('serviceTblCompany', 'bigint', array('notnull' => false));
        }
        if (!$this->getConnection()->hasColumn('tblToCompany', 'serviceTblPerson')) {
            $Table->addColumn('serviceTblPerson', 'bigint', array('notnull' => false));
        }
        $this->getConnection()->addForeignKey($Table, $tblType);
        return $Table;
    }
}
