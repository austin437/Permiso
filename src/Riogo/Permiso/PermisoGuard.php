<?php namespace Riogo\Permiso;

use Illuminate\Auth\Guard;
use Illuminate\Support\Facades\Session;

class PermisoGuard extends Guard {

    /**
     * @var array Array of roles of Authenticated user
     */
    protected $roles;

    /**
     * @var array Array of permissions of Authenticated user
     */
    protected $permissions;

    /**
     * @var bool Flag to check all items from an array
     */
    private $checkAllItems = false;

    /**
     * Check if user have a role
     *
     * @param mixed $role
     * @return bool
     */
    public function hasRole($role)
    {
        return $this->checkItem($role);
    }

    /**
     * Check if user have a permission
     *
     * @param string $permission
     * @return bool
     */
    public function hasPermission($permission)
    {
        return $this->checkItem($permission, 'permissions');
    }

    /**
     * Alias of hasRole
     *
     * @param $role
     * @return bool
     */
    public function is($role)
    {
        return $this->hasRole($role);
    }

    /**
     * Magic method to check a role using is*
     * ex.: isAdmin, isMember, isAuthor, isAnotherRole
     *
     * @param $method
     * @return bool
     */
    public function __call($method, $arguments)
    {
        if(preg_match('/^is/', $method)) {
            return $this->hasRole(
                $this->decamelize(substr($method, 2))
            );
        }
        return false;
    }

    /**
     * Alias of hasPermission
     *
     * @param string $permission
     * @return bool
     */
    public function can($permission)
    {
        return $this->hasPermission($permission);
    }

    /**
     * Activate the flag for check all items
     *
     * @return $this
     */
    public function checkAll()
    {
        $this->checkAllItems = true;
        return $this;
    }

    /**
     * Check if user have a role or a permission, able to check arrays too. Check if one item is true or check all items from array
     *
     * @param string|array $item Item for check, able to be a item or an array of items
     * @param string $type Use 'roles' to check a role or 'permissions' to check a permission
     * @return bool
     */
    private function checkItem($item, $type = 'roles')
    {
        
        $this->loadRolesAndPermissions();   

        if (is_string($item) && strpos($item, ',') !== false) {
            $item = preg_split('/,/', $item);
            $item = array_map('trim', $item);
        }

        if (is_array($item)) {
            if($this->checkAllItems) {
                foreach ($item as $term) {
                    if (array_search($term, $this->{$type}) === false) {
                        return false;
                    }
                }
                $this->checkAllItems = false;
                return true;
            } else {
                foreach ($item as $term) {
                    if (array_search($term, $this->{$type}) !== false) {
                        return true;
                    }
                }
                return false;
            }
        }

        return array_search($item, $this->{$type}) !== false;
    }
    
    
    /**
     * Load permissions from session or if it is empty, load from database.
     *
     * return void()
     */
    private function loadRolesAndPermissions()
    {
            
            $this->permissions = [];
            
            $user = $this->user();
            $this->roles = $user->roles->lists('name');
            if($this->roles instanceof \Illuminate\Database\Eloquent\Collection){
                $this->roles = $this->roles->toArray();
            }
            
            $role_id = $this->user()->roles[0]->id;
        
            $permissions =  \DB::table('role_permission')
                ->join('permissions', 'role_permission.permission_id', '=', 'permissions.id')
                //->join('orders', 'users.id', '=', 'orders.user_id')
                ->select('permissions.name')
                    ->where('role_id', $role_id)
                ->get('name');
            $permissions_array = [];
            foreach($permissions as $permission)
            {
                array_push($permissions_array,$permission->name);

            };
            
            $this->permissions = $permissions_array;
        
    }

    /**
     * Remove the user roles and permissions from session.
     *
     * return void()
     */
    protected function clearUserDataFromStorage()
    {
        $this->session->remove('roles');
        $this->session->remove('permissions');

        $this->roles = [];
        $this->permissions = [];

        parent::clearUserDataFromStorage();
    }

    /**
     * Helper for transform CamelCase in camel_case
     *
     * @param $word
     * @return string
     */
    private function decamelize($word) {
        return trim(
            preg_replace_callback(
                '/([A-Z])/',
                function ($matches) {
                    return strtolower('_' . $matches[0]);
                },
                $word
            )
        , '_');
    }
}